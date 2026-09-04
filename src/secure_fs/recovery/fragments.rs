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
                    self.finish_current_directory(&mut batch);
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

    fn finish_current_directory(&mut self, batch: &mut UploadFragmentCleanupBatch) {
        let completed = self
            .directories
            .pop()
            .expect("cleanup directory disappeared");
        if completed.policy == CleanupPolicy::DeleteAll {
            let Some((parent, name)) = completed.remove_from else {
                batch.failed += 1;
                return;
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
