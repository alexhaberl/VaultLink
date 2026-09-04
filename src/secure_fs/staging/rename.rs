impl SecureRoot {
    pub fn stage_rename(&self, relative: &str, new_name: &str) -> io::Result<StagedRename> {
        match self.stage_rename_with_outcome(relative, new_name)? {
            RenameStageOutcome::Ready(staged) => Ok(staged),
            RenameStageOutcome::PublishedUncertain { error, .. } => Err(error),
        }
    }

    pub(crate) fn stage_rename_with_outcome(
        &self,
        relative: &str,
        new_name: &str,
    ) -> io::Result<RenameStageOutcome> {
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
        if let Some(outcome) = self.reconcile_rename_result(
            &parent,
            &original_name,
            new_name,
            &original_path,
            &new_path,
            source_identity,
            kind,
            &operation_name,
            rename,
        )? {
            return Ok(outcome);
        }
        // Do not let SQLite observe the new path until the directory entry is
        // durable. If fsync fails, the journal deliberately remains for startup
        // recovery instead of pretending that the cross-resource commit ended.
        if let Err(error) = self.sync_rename_parent(&transaction_parent) {
            return Ok(RenameStageOutcome::PublishedUncertain {
                new_path,
                kind,
                error,
            });
        }
        if let Err(error) = replace_file_operation(
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
        ) {
            return Ok(RenameStageOutcome::PublishedUncertain {
                new_path,
                kind,
                error,
            });
        }
        Ok(RenameStageOutcome::Ready(StagedRename {
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
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn reconcile_rename_result(
        &self,
        parent: &SecureDirectory,
        original_name: &str,
        new_name: &str,
        original_path: &str,
        new_path: &str,
        source_identity: (u64, u64),
        kind: EntryKind,
        operation_name: &str,
        rename: io::Result<()>,
    ) -> io::Result<Option<RenameStageOutcome>> {
        let destination_state = match entry_identity_state(
            parent.directory.as_ref(),
            new_name,
            source_identity,
            kind,
        ) {
            Ok(state) => state,
            Err(error) => {
                return Ok(Some(RenameStageOutcome::PublishedUncertain {
                    new_path: new_path.to_string(),
                    kind,
                    error,
                }));
            }
        };
        match (rename, destination_state) {
            (Ok(()), EntryIdentityState::Expected) => {}
            (Ok(()), EntryIdentityState::Missing) => {
                return Ok(Some(RenameStageOutcome::PublishedUncertain {
                    new_path: new_path.to_string(),
                    kind,
                    error: io::Error::new(
                        io::ErrorKind::NotFound,
                        "rename destination disappeared before identity verification",
                    ),
                }));
            }
            (Ok(()), EntryIdentityState::Replaced) => {
                return Ok(Some(RenameStageOutcome::PublishedUncertain {
                    new_path: new_path.to_string(),
                    kind,
                    error: io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "rename destination was replaced after publication",
                    ),
                }));
            }
            (Err(error), EntryIdentityState::Expected) => {
                let source_state = match entry_identity_state(
                    parent.directory.as_ref(),
                    original_name,
                    source_identity,
                    kind,
                ) {
                    Ok(state) => state,
                    Err(probe_error) => {
                        return Ok(Some(RenameStageOutcome::PublishedUncertain {
                            new_path: new_path.to_string(),
                            kind,
                            error: io::Error::new(
                                probe_error.kind(),
                                format!(
                                    "rename result and source identity are uncertain: {error}; {probe_error}"
                                ),
                            ),
                        }));
                    }
                };
                match source_state {
                    EntryIdentityState::Expected => {
                        remove_file_operation(self.tombstones.as_ref(), operation_name)?;
                        return Err(error);
                    }
                    EntryIdentityState::Missing => {}
                    EntryIdentityState::Replaced => {
                        return Ok(Some(RenameStageOutcome::PublishedUncertain {
                            new_path: new_path.to_string(),
                            kind,
                            error,
                        }));
                    }
                }
                tracing::warn!(
                    error = %EscapedLogValue::new(&error),
                    from = %EscapedLogPath::new(&original_path),
                    to = %EscapedLogPath::new(&new_path),
                    "rename returned an error after the entry moved; continuing with verified identity"
                );
            }
            (Err(error), EntryIdentityState::Missing | EntryIdentityState::Replaced) => {
                let source_state = match entry_identity_state(
                    parent.directory.as_ref(),
                    original_name,
                    source_identity,
                    kind,
                ) {
                    Ok(state) => state,
                    Err(probe_error) => {
                        return Ok(Some(RenameStageOutcome::PublishedUncertain {
                            new_path: new_path.to_string(),
                            kind,
                            error: io::Error::new(
                                probe_error.kind(),
                                format!(
                                    "rename result and source identity are uncertain: {error}; {probe_error}"
                                ),
                            ),
                        }));
                    }
                };
                if source_state == EntryIdentityState::Expected {
                    remove_file_operation(self.tombstones.as_ref(), operation_name)?;
                    return Err(error);
                }
                return Ok(Some(RenameStageOutcome::PublishedUncertain {
                    new_path: new_path.to_string(),
                    kind,
                    error,
                }));
            }
        }
        Ok(None)
    }

    fn sync_rename_parent(&self, parent: &std::fs::File) -> io::Result<()> {
        #[cfg(test)]
        if let Some(kind) = self
            .next_rename_parent_sync_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            return Err(io::Error::new(kind, "injected renamed-parent sync failure"));
        }
        parent.sync_all()
    }

    #[cfg(test)]
    pub(crate) fn fail_next_rename_parent_sync(&self, kind: io::ErrorKind) {
        *self
            .next_rename_parent_sync_error
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
                tracing::error!(
                    error = %EscapedLogValue::new(&error),
                    from = %EscapedLogPath::new(&self.new_path),
                    to = %EscapedLogPath::new(&self.original_path),
                    "could not roll back staged rename"
                );
            }
        }
    }
}
