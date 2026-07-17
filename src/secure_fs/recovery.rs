use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::Arc,
};

use super::identity::{entry_exists, entry_identity_state, entry_matches_identity};
use super::journal::{
    read_file_operation, read_pending_manifest, remove_file_operation, remove_pending_manifest,
    replace_delete_operation_phase, replace_file_operation,
};
use super::private_entries::{
    active_upload_fragment_guard, is_upload_fragment_name, unregister_upload_fragment,
};
use super::{
    cleanup_segment_name, deletion_manifest_name, deletion_pending_from_manifest_name,
    is_deletion_pending_name, is_deletion_tombstone_name, is_file_operation_name,
    is_file_operation_temporary_name, linux, split_parent_name, split_parent_name_private,
    CleanupDirectory, CleanupPolicy, DurableDeletePhase, DurableFileOperation, DurableRenamePhase,
    EntryIdentityState, EntryKind, FileOperationRecovery, PendingFileOperation, SecureDirectory,
    SecureRoot, UploadFragmentCleanup, UploadFragmentCleanupBatch, MAX_CLEANUP_DIRECTORY_STACK,
    MAX_CLEANUP_VISITED_DIRECTORIES,
};

impl UploadFragmentCleanup {
    pub fn run_batch(&mut self, max_entries: usize) -> io::Result<UploadFragmentCleanupBatch> {
        if max_entries == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "upload fragment cleanup batch size must be positive",
            ));
        }
        #[cfg(test)]
        if let Some(hook) = self.before_batch_hook.as_ref().and_then(|hook| {
            hook.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
        }) {
            hook();
        }
        #[cfg(test)]
        if let Some(kind) = self.next_batch_error.as_ref().and_then(|error| {
            error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
        }) {
            return Err(io::Error::new(kind, "injected cleanup batch failure"));
        }
        self.run_linux_batch(max_entries)
    }

    fn run_linux_batch(&mut self, max_entries: usize) -> io::Result<UploadFragmentCleanupBatch> {
        use std::os::unix::fs::MetadataExt;

        let mut batch = UploadFragmentCleanupBatch::default();
        while batch.scanned < max_entries {
            let directory_stack_len = self.directories.len();
            let Some(current) = self.directories.last_mut() else {
                batch.complete = true;
                break;
            };
            let item = match current.entries.next() {
                Some(Ok(item)) => item,
                Some(Err(_)) => {
                    batch.scanned += 1;
                    batch.failed += 1;
                    continue;
                }
                None => {
                    let completed = self
                        .directories
                        .pop()
                        .expect("cleanup directory disappeared");
                    if completed.policy == CleanupPolicy::DeleteAll {
                        let Some((parent, name)) = completed.remove_from else {
                            batch.failed += 1;
                            continue;
                        };
                        match linux::rmdir(&parent, &name) {
                            Ok(()) => {
                                batch.removed += 1;
                                if let Some(parent) = self.directories.last_mut() {
                                    parent.removed_in_pass = true;
                                }
                            }
                            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                            Err(_) => batch.failed += 1,
                        }
                    } else if completed.removed_in_pass {
                        match cleanup_directory_from_file(&completed.directory, completed.policy) {
                            Ok(directory) => self.directories.push(directory),
                            Err(_) => batch.failed += 1,
                        }
                    }
                    continue;
                }
            };
            batch.scanned += 1;
            let name = item.file_name();
            if current.policy == CleanupPolicy::TombstoneRoot {
                if is_deletion_pending_name(&name) {
                    continue;
                }
                if is_deletion_tombstone_name(&name) {
                    if let Some(staging) = self.operation_staging.as_ref() {
                        if deletion_tombstone_has_durable_intent(staging, &name)? {
                            continue;
                        }
                    }
                }
            }
            if name
                .to_str()
                .is_some_and(|name| active_upload_fragment_guard().contains(name))
            {
                continue;
            }
            let child = match linux::openat2_scoped(
                &current.directory,
                &name,
                linux::O_PATH | linux::O_NOFOLLOW,
                true,
            ) {
                Ok(child) => child,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => {
                    batch.failed += 1;
                    continue;
                }
            };
            let metadata = match child.metadata() {
                Ok(metadata) => metadata,
                Err(_) => {
                    batch.failed += 1;
                    continue;
                }
            };
            if metadata.is_dir() {
                let child_policy = match current.policy {
                    CleanupPolicy::DeleteAll => Some(CleanupPolicy::DeleteAll),
                    CleanupPolicy::TombstoneRoot if is_deletion_tombstone_name(&name) => {
                        Some(CleanupPolicy::DeleteAll)
                    }
                    // Upload staging is flat, and pending/recovery tombstones
                    // must survive as whole subtrees until an operator resolves
                    // them. Never recurse into any other private directory.
                    CleanupPolicy::UploadFragments | CleanupPolicy::TombstoneRoot => None,
                };
                if let Some(child_policy) = child_policy {
                    let identity = (metadata.dev(), metadata.ino());
                    if !self.visited.contains(&identity) {
                        if directory_stack_len >= self.max_directory_stack {
                            // Move the current deep subtree back to level one
                            // of the same tombstone before asking the worker to
                            // restart. This keeps the descriptor stack bounded
                            // while guaranteeing that every retry shortens the
                            // deepest remaining path.
                            rebase_cleanup_directory(current)?;
                            return Err(io::Error::new(
                                io::ErrorKind::WouldBlock,
                                "recursive cleanup directory-stack limit reached; the deep subtree was segmented for a bounded retry",
                            ));
                        }
                        if self.visited.len() >= self.max_visited_directories {
                            return Err(io::Error::new(
                                io::ErrorKind::WouldBlock,
                                "recursive cleanup visited-directory limit reached; restart the cleanup cursor to retry",
                            ));
                        }
                        self.visited.insert(identity);
                        let starts_deletion_root = current.policy == CleanupPolicy::TombstoneRoot;
                        let inherited_deletion_root = current.deletion_root.clone();
                        match cleanup_directory_from_file(&child, child_policy) {
                            Ok(mut directory) => {
                                directory.remove_from =
                                    Some((current.directory.try_clone()?, name.clone()));
                                directory.deletion_root = if starts_deletion_root {
                                    // cleanup_directory_from_file upgrades the
                                    // O_PATH probe to a readable directory FD;
                                    // retain that capability because rebasing
                                    // must fsync the tombstone root.
                                    Some(Arc::new(directory.directory.try_clone()?))
                                } else {
                                    inherited_deletion_root
                                };
                                self.directories.push(directory);
                            }
                            Err(_) => batch.failed += 1,
                        }
                    }
                }
            } else if current.policy == CleanupPolicy::DeleteAll
                || (current.policy == CleanupPolicy::UploadFragments
                    && metadata.is_file()
                    && is_upload_fragment_name(&name))
                || (current.policy == CleanupPolicy::TombstoneRoot
                    && is_deletion_tombstone_name(&name))
            {
                match linux::unlink(&current.directory, &name) {
                    Ok(()) => {
                        current.removed_in_pass = true;
                        batch.removed += 1;
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => batch.failed += 1,
                }
            }
        }
        batch.complete = self.directories.is_empty();
        Ok(batch)
    }
}

fn deletion_tombstone_has_durable_intent(
    staging: &File,
    tombstone_name: &OsStr,
) -> io::Result<bool> {
    use std::os::fd::AsRawFd;

    if !is_deletion_tombstone_name(tombstone_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid deletion tombstone",
        ));
    }
    let proc_path = format!("/proc/self/fd/{}", staging.as_raw_fd());
    for item in std::fs::read_dir(proc_path)? {
        let name = item?.file_name();
        if !is_file_operation_name(&name) {
            continue;
        }
        let name = name.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "file-operation journal has a non-UTF-8 name",
            )
        })?;
        let operation = match read_file_operation(staging, name) {
            Ok(operation) => operation,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        validate_file_operation(&operation)?;
        if let DurableFileOperation::Delete {
            tombstone_name: protected,
            ..
        } = operation
        {
            if OsStr::new(&protected) == tombstone_name {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

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

impl SecureRoot {
    pub(super) fn remove_incomplete_file_operation_writes(&self) -> io::Result<()> {
        use std::os::fd::AsRawFd;

        let proc_path = format!("/proc/self/fd/{}", self.tombstones.as_ref().as_raw_fd());
        let mut removed = false;
        for item in std::fs::read_dir(proc_path)? {
            let name = item?.file_name();
            let should_remove = if is_file_operation_temporary_name(&name) {
                true
            } else if let Some(pending_name) = deletion_pending_from_manifest_name(&name) {
                !entry_exists(self.tombstones.as_ref(), pending_name)?
            } else {
                false
            };
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

    pub(super) fn recover_pending_deletions(
        &self,
        pending_operations: &[PendingFileOperation],
    ) -> io::Result<()> {
        use std::os::fd::AsRawFd;

        let journaled_pending: HashSet<&str> = pending_operations
            .iter()
            .filter_map(|pending| match &pending.operation {
                DurableFileOperation::Delete { pending_name, .. } => Some(pending_name.as_str()),
                DurableFileOperation::Rename { .. } => None,
            })
            .collect();
        let proc_path = format!("/proc/self/fd/{}", self.tombstones.as_ref().as_raw_fd());
        for item in std::fs::read_dir(proc_path)? {
            let item = item?;
            let pending_name = item.file_name();
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
            remove_pending_manifest(self.tombstones.as_ref(), &manifest_name)?;
            tracing::warn!(recovery_entry = %pending_name, original = %original_path, "restored uncommitted deletion after restart");
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

    fn recover_rename_operation(
        &self,
        operation_name: &str,
        original_path: &str,
        new_path: &str,
        kind: EntryKind,
        identity: (u64, u64),
        phase: DurableRenamePhase,
    ) -> io::Result<FileOperationRecovery> {
        let (original_parent, original_name) = split_parent_name(original_path)?;
        let (new_parent, new_name) = split_parent_name(new_path)?;
        if original_parent != new_parent {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "rename recovery journal crosses parent directories",
            ));
        }
        let parent = self.root.bind_directory(&original_parent)?;
        match phase {
            DurableRenamePhase::Intent => {
                match entry_identity_state(parent.directory.as_ref(), &new_name, identity, kind)? {
                    EntryIdentityState::Expected => parent.directory.sync_all()?,
                    EntryIdentityState::Replaced => {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "rename recovery destination was replaced by another object",
                        ));
                    }
                    EntryIdentityState::Missing => match entry_identity_state(
                        parent.directory.as_ref(),
                        &original_name,
                        identity,
                        kind,
                    )? {
                        EntryIdentityState::Expected => {
                            // Intent was durable before the filesystem rename,
                            // so this state is ambiguous: it can be the original
                            // source or an inode-reusing replacement after a
                            // completed target was removed. Never replay a
                            // name-based move. SQLite is still unchanged at this
                            // phase, so cancel the operation in place.
                            remove_file_operation(self.tombstones.as_ref(), operation_name)?;
                            return Ok(FileOperationRecovery::Cancelled);
                        }
                        EntryIdentityState::Replaced => {
                            return Err(io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                "rename recovery source was replaced by another object",
                            ));
                        }
                        EntryIdentityState::Missing => {
                            // A new-format intent is durable before the rename.
                            // If neither name contains the authorized inode we
                            // cannot prove the syscall ran; never rewrite DB
                            // paths based only on a name-level guess.
                            return Err(io::Error::new(
                                io::ErrorKind::NotFound,
                                "rename intent target is missing under both names",
                            ));
                        }
                    },
                }
                replace_file_operation(
                    self.tombstones.as_ref(),
                    operation_name,
                    &DurableFileOperation::Rename {
                        original_path: original_path.to_string(),
                        new_path: new_path.to_string(),
                        kind: kind.into(),
                        device: identity.0,
                        inode: identity.1,
                        phase: DurableRenamePhase::Moved,
                    },
                )?;
            }
            DurableRenamePhase::Moved => {
                match entry_identity_state(parent.directory.as_ref(), &new_name, identity, kind)? {
                    EntryIdentityState::Expected => parent.directory.sync_all()?,
                    EntryIdentityState::Replaced => {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "completed rename destination was replaced by another object",
                        ));
                    }
                    EntryIdentityState::Missing => {
                        // Never use the old name to reconstruct a completed move:
                        // dev/inode may have been recycled for a replacement.
                        tracing::warn!(from = %original_path, to = %new_path, "completed rename target is missing; old-path replacements were preserved");
                    }
                }
            }
            DurableRenamePhase::Rollback => {
                let original_state = entry_identity_state(
                    parent.directory.as_ref(),
                    &original_name,
                    identity,
                    kind,
                )?;
                let destination_state =
                    entry_identity_state(parent.directory.as_ref(), &new_name, identity, kind)?;
                match (original_state, destination_state) {
                    (EntryIdentityState::Expected, EntryIdentityState::Missing) => {
                        parent.directory.sync_all()?;
                    }
                    (EntryIdentityState::Missing, EntryIdentityState::Expected) => {
                        linux::rename_noreplace(
                            parent.directory.as_ref(),
                            &new_name,
                            &original_name,
                        )?;
                        parent.directory.sync_all()?;
                    }
                    (EntryIdentityState::Replaced, _) => {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "rename rollback source was replaced by another object",
                        ));
                    }
                    (_, EntryIdentityState::Replaced) => {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "rename rollback destination was replaced by another object",
                        ));
                    }
                    (EntryIdentityState::Expected, EntryIdentityState::Expected) => {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "rename rollback identity appears under both names",
                        ));
                    }
                    (EntryIdentityState::Missing, EntryIdentityState::Missing) => {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "rename rollback target is missing under both names",
                        ));
                    }
                }
                remove_file_operation(self.tombstones.as_ref(), operation_name)?;
                return Ok(FileOperationRecovery::Cancelled);
            }
        }
        Ok(FileOperationRecovery::Rename {
            original_path: original_path.to_string(),
            new_path: new_path.to_string(),
            is_directory: kind == EntryKind::Directory,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_delete_rollback(
        &self,
        operation_name: &str,
        original_path: &str,
        kind: EntryKind,
        identity: (u64, u64),
        pending_name: &str,
        tombstone_name: &str,
    ) -> io::Result<FileOperationRecovery> {
        let (parent_path, original_name) = split_parent_name(original_path)?;
        let parent = self.root.bind_directory(&parent_path)?;
        let original_state =
            entry_identity_state(parent.directory.as_ref(), &original_name, identity, kind)?;
        let pending_state =
            entry_identity_state(self.tombstones.as_ref(), pending_name, identity, kind)?;
        let tombstone_state =
            entry_identity_state(self.tombstones.as_ref(), tombstone_name, identity, kind)?;

        if original_state == EntryIdentityState::Replaced {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "delete rollback destination was replaced by another object",
            ));
        }
        if pending_state == EntryIdentityState::Replaced
            || tombstone_state == EntryIdentityState::Replaced
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "delete rollback private entry was replaced by another object",
            ));
        }

        let private_source = match (pending_state, tombstone_state) {
            (EntryIdentityState::Expected, EntryIdentityState::Missing) => Some(pending_name),
            (EntryIdentityState::Missing, EntryIdentityState::Expected) => Some(tombstone_name),
            (EntryIdentityState::Missing, EntryIdentityState::Missing) => None,
            (EntryIdentityState::Expected, EntryIdentityState::Expected) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "delete rollback identity appears under both private names",
                ));
            }
            _ => unreachable!("replaced states handled above"),
        };

        match (original_state, private_source) {
            (EntryIdentityState::Expected, None) => {
                // The namespace rollback already completed before the crash.
                parent.directory.sync_all()?;
            }
            (EntryIdentityState::Expected, Some(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "delete rollback identity appears under visible and private names",
                ));
            }
            (EntryIdentityState::Missing, Some(private_name)) => {
                let rename = linux::rename_noreplace_between(
                    self.tombstones.as_ref(),
                    private_name,
                    parent.directory.as_ref(),
                    &original_name,
                );
                if let Err(error) = rename {
                    let restored = entry_matches_identity(
                        parent.directory.as_ref(),
                        &original_name,
                        identity,
                        kind,
                    ) && !entry_exists(self.tombstones.as_ref(), private_name)?;
                    if !restored {
                        return Err(error);
                    }
                    tracing::warn!(%error, original = %original_path, "delete rollback rename returned an error after restoration; continuing with verified identity");
                }
                // A cross-directory rename is durable only after syncing the
                // destination before the source directory.
                parent.directory.sync_all()?;
                self.tombstones.sync_all()?;
            }
            (EntryIdentityState::Missing, None) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "delete rollback target is missing under all recovery names",
                ));
            }
            (EntryIdentityState::Replaced, _) => unreachable!("handled above"),
        }

        remove_pending_manifest(
            self.tombstones.as_ref(),
            &deletion_manifest_name(pending_name),
        )?;
        remove_file_operation(self.tombstones.as_ref(), operation_name)?;
        unregister_upload_fragment(pending_name);
        unregister_upload_fragment(tombstone_name);
        Ok(FileOperationRecovery::Cancelled)
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_delete_operation(
        &self,
        operation_name: &str,
        original_path: &str,
        kind: EntryKind,
        identity: (u64, u64),
        pending_name: &str,
        tombstone_name: &str,
        allow_recursive: bool,
        phase: DurableDeletePhase,
    ) -> io::Result<FileOperationRecovery> {
        if matches!(
            phase,
            DurableDeletePhase::Intent | DurableDeletePhase::Rollback
        ) {
            return self.recover_delete_rollback(
                operation_name,
                original_path,
                kind,
                identity,
                pending_name,
                tombstone_name,
            );
        }
        let (parent_path, original_name) = split_parent_name(original_path)?;
        let parent = self.root.bind_directory(&parent_path)?;
        let tombstone_present =
            entry_matches_identity(self.tombstones.as_ref(), tombstone_name, identity, kind);
        if !tombstone_present {
            if entry_exists(self.tombstones.as_ref(), tombstone_name)? {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "delete recovery tombstone was replaced by another object",
                ));
            }
            if entry_matches_identity(self.tombstones.as_ref(), pending_name, identity, kind) {
                linux::rename_noreplace(self.tombstones.as_ref(), pending_name, tombstone_name)?;
                self.tombstones.sync_all()?;
            } else if entry_exists(self.tombstones.as_ref(), pending_name)? {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "pending delete recovery entry was replaced by another object",
                ));
            } else {
                // A durable delete journal is published only after the source
                // has moved to the private pending name. If both private names
                // are now absent, the physical operation completed or was
                // externally resolved. Always preserve a visible object at the
                // old path: dev/inode values can be reused after unlink, so they
                // cannot safely prove it is the original target.
                remove_pending_manifest(
                    self.tombstones.as_ref(),
                    &deletion_manifest_name(pending_name),
                )?;
                return Ok(FileOperationRecovery::Delete {
                    original_path: original_path.to_string(),
                    is_directory: kind == EntryKind::Directory,
                    tombstone_path: None,
                });
            }
        }

        remove_pending_manifest(
            self.tombstones.as_ref(),
            &deletion_manifest_name(pending_name),
        )?;
        match kind {
            EntryKind::File => {
                match linux::unlink(self.tombstones.as_ref(), tombstone_name) {
                    Ok(()) => self.tombstones.sync_all()?,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                Ok(FileOperationRecovery::Delete {
                    original_path: original_path.to_string(),
                    is_directory: false,
                    tombstone_path: None,
                })
            }
            EntryKind::Directory if allow_recursive => Ok(FileOperationRecovery::Delete {
                original_path: original_path.to_string(),
                is_directory: true,
                tombstone_path: Some(tombstone_name.to_string()),
            }),
            EntryKind::Directory => match linux::rmdir(self.tombstones.as_ref(), tombstone_name) {
                Ok(()) => {
                    self.tombstones.sync_all()?;
                    Ok(FileOperationRecovery::Delete {
                        original_path: original_path.to_string(),
                        is_directory: true,
                        tombstone_path: None,
                    })
                }
                Err(error) => match self.deletion_tombstone_identity_state(
                    tombstone_name,
                    identity,
                    EntryKind::Directory,
                )? {
                    EntryIdentityState::Missing => {
                        self.tombstones.sync_all()?;
                        Ok(FileOperationRecovery::Delete {
                            original_path: original_path.to_string(),
                            is_directory: true,
                            tombstone_path: None,
                        })
                    }
                    EntryIdentityState::Replaced => Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "delete recovery tombstone was replaced",
                    )),
                    EntryIdentityState::Expected
                        if error.kind() == io::ErrorKind::DirectoryNotEmpty =>
                    {
                        replace_delete_operation_phase(
                            self.tombstones.as_ref(),
                            operation_name,
                            DurableDeletePhase::Rollback,
                        )?;
                        linux::rename_noreplace_between(
                            self.tombstones.as_ref(),
                            tombstone_name,
                            parent.directory.as_ref(),
                            &original_name,
                        )?;
                        // Persist the restored destination before the private
                        // source removal for cross-directory rename safety.
                        parent.directory.sync_all()?;
                        self.tombstones.sync_all()?;
                        remove_file_operation(self.tombstones.as_ref(), operation_name)?;
                        unregister_upload_fragment(tombstone_name);
                        Ok(FileOperationRecovery::Cancelled)
                    }
                    EntryIdentityState::Expected => Err(error),
                },
            },
        }
    }
}

impl SecureDirectory {
    /// Starts a recursive cleanup cursor suitable for bounded background batches.
    /// Uploads active in this process are registered and cannot be removed by it.
    pub fn start_upload_fragment_cleanup(&self) -> io::Result<UploadFragmentCleanup> {
        start_cleanup_from_directory(
            self.staging.as_ref(),
            CleanupPolicy::UploadFragments,
            self._storage_instance_lock.clone(),
        )
    }
}

fn cleanup_directory_from_file(
    directory: &File,
    policy: CleanupPolicy,
) -> io::Result<CleanupDirectory> {
    use std::os::fd::AsRawFd;

    // Descendants are initially probed with O_PATH so metadata checks cannot
    // block on special files. Upgrade the already-bound directory capability
    // to O_RDONLY: unlinkat/openat still stay descriptor-relative, while fsync
    // during depth segmentation now works instead of failing with EBADF.
    let directory = linux::openat2_scoped(
        directory,
        ".",
        linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
        true,
    )?;
    let proc_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let entries = std::fs::read_dir(proc_path)?;
    Ok(CleanupDirectory {
        directory,
        entries,
        removed_in_pass: false,
        policy,
        remove_from: None,
        deletion_root: None,
    })
}

/// Shortens an over-deep cleanup path without moving any entry outside its
/// deletion tombstone. The rename is atomic and crash-safe in either namespace
/// position; syncing both affected directories makes the progress durable when
/// the filesystem supports directory fsync.
pub(super) fn rebase_cleanup_directory(directory: &CleanupDirectory) -> io::Result<()> {
    let deletion_root = directory.deletion_root.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "recursive cleanup lost its deletion-root capability",
        )
    })?;
    let (parent, original_name) = directory.remove_from.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "recursive cleanup cannot segment its deletion root",
        )
    })?;

    let current_metadata = directory.directory.metadata()?;
    let root_metadata = deletion_root.metadata()?;
    if (current_metadata.dev(), current_metadata.ino())
        == (root_metadata.dev(), root_metadata.ino())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recursive cleanup cannot move its deletion root into itself",
        ));
    }
    let identity = (current_metadata.dev(), current_metadata.ino());

    for _ in 0..16 {
        if cleanup_directory_identity_state(parent, original_name.as_os_str(), identity)?
            != EntryIdentityState::Expected
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "recursive cleanup source changed before segmentation; restart the cleanup cursor",
            ));
        }
        let segment_name = cleanup_segment_name();
        if let Err(rename_error) = linux::rename_noreplace_between(
            parent,
            Path::new(original_name),
            deletion_root,
            Path::new(&segment_name),
        ) {
            match cleanup_directory_identity_state(
                deletion_root,
                OsStr::new(&segment_name),
                identity,
            ) {
                // Network filesystems can report a failed rename after the
                // server applied it. Treat the expected target identity as the
                // authoritative outcome.
                Ok(EntryIdentityState::Expected) => {}
                Ok(EntryIdentityState::Missing | EntryIdentityState::Replaced)
                    if rename_error.kind() == io::ErrorKind::AlreadyExists =>
                {
                    continue;
                }
                Ok(EntryIdentityState::Missing | EntryIdentityState::Replaced) => {
                    return Err(rename_error);
                }
                Err(probe_error) => return Err(probe_error),
            }
        }

        if cleanup_directory_identity_state(deletion_root, OsStr::new(&segment_name), identity)?
            != EntryIdentityState::Expected
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "recursive cleanup segment changed after rename; restart the cleanup cursor",
            ));
        }
        // Persist the destination before the source removal. After a power
        // loss this ordering cannot strand the subtree outside both names.
        deletion_root.sync_all()?;
        parent.sync_all()?;
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "could not allocate a private cleanup-segment name; retry the cleanup cursor",
    ))
}

fn cleanup_directory_identity_state(
    directory: &File,
    name: &OsStr,
    expected: (u64, u64),
) -> io::Result<EntryIdentityState> {
    let entry = match linux::openat2_scoped(
        directory,
        Path::new(name),
        linux::O_PATH | linux::O_NOFOLLOW,
        true,
    ) {
        Ok(entry) => entry,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(EntryIdentityState::Missing);
        }
        Err(error) => return Err(error),
    };
    let metadata = entry.metadata()?;
    Ok(
        if metadata.is_dir() && (metadata.dev(), metadata.ino()) == expected {
            EntryIdentityState::Expected
        } else {
            EntryIdentityState::Replaced
        },
    )
}

pub(super) fn start_cleanup_from_directory(
    root: &File,
    policy: CleanupPolicy,
    storage_instance_lock: Option<Arc<crate::StorageInstanceLock>>,
) -> io::Result<UploadFragmentCleanup> {
    use std::os::unix::fs::MetadataExt;

    let root = root.try_clone()?;
    let metadata = root.metadata()?;
    let directory = cleanup_directory_from_file(&root, policy)?;
    Ok(UploadFragmentCleanup {
        directories: vec![directory],
        visited: HashSet::from([(metadata.dev(), metadata.ino())]),
        max_directory_stack: MAX_CLEANUP_DIRECTORY_STACK,
        max_visited_directories: MAX_CLEANUP_VISITED_DIRECTORIES,
        operation_staging: None,
        _storage_instance_lock: storage_instance_lock,
        #[cfg(test)]
        next_batch_error: None,
        #[cfg(test)]
        before_batch_hook: None,
    })
}
