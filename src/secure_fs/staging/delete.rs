fn source_is_unchanged_and_pending_is_foreign(
    source_state: &io::Result<EntryIdentityState>,
    pending_state: &io::Result<EntryIdentityState>,
) -> bool {
    matches!(source_state, Ok(EntryIdentityState::Expected))
        && matches!(
            pending_state,
            Ok(EntryIdentityState::Missing | EntryIdentityState::Replaced)
        )
}

impl SecureRoot {
    #[cfg(test)]
    pub(super) fn stage_delete_ready(&self, relative: &str) -> io::Result<StagedDelete> {
        match self.stage_delete(relative)? {
            DeleteStageOutcome::Ready(staged) => Ok(*staged),
            DeleteStageOutcome::PublishedUncertain { error, .. } => Err(error),
        }
    }

    pub(crate) fn stage_delete(&self, relative: &str) -> io::Result<DeleteStageOutcome> {
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
        let (tombstone_name, manifest_name) = match self.stage_pending_delete(
            &parent,
            &original_name,
            &original_path,
            source_identity,
            source_kind,
        )? {
            PendingDeleteStage::Ready {
                tombstone_name,
                manifest_name,
            } => (tombstone_name, manifest_name),
            PendingDeleteStage::PublishedUncertain(error) => {
                return Ok(DeleteStageOutcome::PublishedUncertain {
                    original_path,
                    kind: source_kind,
                    error,
                });
            }
        };
        let active_key = tombstone_name.clone();
        let status = match self.inspect_pending_delete(
            &parent,
            &tombstone_name,
            source_identity,
            &source_metadata,
        ) {
            Ok(status) => status,
            Err(error) => {
                return self.reconcile_failed_delete_stage(
                    error,
                    &tombstone_name,
                    &manifest_name,
                    parent.directory.as_ref(),
                    &original_name,
                    &original_path,
                    source_identity,
                    source_kind,
                );
            }
        };
        Ok(DeleteStageOutcome::Ready(Box::new(StagedDelete {
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
            next_commit_sync_error: self.next_delete_commit_sync_error.clone(),
            #[cfg(test)]
            after_promotion_hook: None,
        })))
    }

    fn stage_pending_delete(
        &self,
        parent: &SecureDirectory,
        original_name: &str,
        original_path: &str,
        source_identity: (u64, u64),
        source_kind: EntryKind,
    ) -> io::Result<PendingDeleteStage> {
        let source = PendingDeleteSource {
            parent,
            original_name,
            original_path,
            identity: source_identity,
            kind: source_kind,
        };
        loop {
            let Some((candidate, manifest_name)) =
                self.prepare_pending_delete_candidate(original_path)?
            else {
                continue;
            };
            let rename = linux::rename_noreplace_between(
                parent.directory.as_ref(),
                original_name,
                self.tombstones.as_ref(),
                &candidate,
            );
            #[cfg(test)]
            let rename = inject_error_after_successful_rename(
                rename,
                self.next_delete_staging_rename_error.as_ref(),
            );
            match rename {
                Ok(()) => {
                    return Ok(PendingDeleteStage::Ready {
                        tombstone_name: candidate,
                        manifest_name,
                    });
                }
                Err(error) => match self.reconcile_pending_delete_rename(
                    &source,
                    candidate,
                    manifest_name,
                    error,
                )? {
                    Some(outcome) => return Ok(outcome),
                    None => continue,
                },
            }
        }
    }

    fn prepare_pending_delete_candidate(
        &self,
        original_path: &str,
    ) -> io::Result<Option<(String, String)>> {
        let candidate = deletion_pending_name();
        // Register before any staging I/O. Cleanup can never observe the
        // renamed pending entry before its active name is published.
        if !active_upload_fragment_guard().insert(candidate.clone()) {
            return Ok(None);
        }
        match write_pending_manifest(self.tombstones.as_ref(), &candidate, original_path) {
            Ok(manifest_name) => Ok(Some((candidate, manifest_name))),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                unregister_upload_fragment(&candidate);
                Ok(None)
            }
            Err(error) => {
                unregister_upload_fragment(&candidate);
                Err(error)
            }
        }
    }

    fn reconcile_pending_delete_rename(
        &self,
        source: &PendingDeleteSource<'_>,
        candidate: String,
        manifest_name: String,
        rename_error: io::Error,
    ) -> io::Result<Option<PendingDeleteStage>> {
        let pending_state = self.delete_staging_identity_state(
            self.tombstones.as_ref(),
            &candidate,
            source.identity,
            source.kind,
        );
        if matches!(&pending_state, Ok(EntryIdentityState::Expected)) {
            tracing::warn!(
                error = %EscapedLogValue::new(&rename_error),
                pending = %EscapedLogPath::new(&candidate),
                original = %EscapedLogPath::new(source.original_path),
                "delete staging rename returned an error after the source became pending; continuing with verified identity"
            );
            return Ok(Some(PendingDeleteStage::Ready {
                tombstone_name: candidate,
                manifest_name,
            }));
        }
        let source_state = self.delete_staging_identity_state(
            source.parent.directory.as_ref(),
            source.original_name,
            source.identity,
            source.kind,
        );
        if source_is_unchanged_and_pending_is_foreign(&source_state, &pending_state) {
            self.discard_unused_pending_delete(&candidate, &manifest_name);
            if rename_error.kind() == io::ErrorKind::AlreadyExists {
                return Ok(None);
            }
            return Err(rename_error);
        }

        let error = ambiguous_delete_stage_error(&rename_error, &pending_state, &source_state);
        tracing::error!(
            error = %EscapedLogValue::new(&error),
            recovery_entry = %EscapedLogPath::new(&candidate),
            manifest = %EscapedLogPath::new(&manifest_name),
            original = %EscapedLogPath::new(source.original_path),
            "delete staging rename outcome is visible or ambiguous; recovery metadata was preserved"
        );
        Ok(Some(PendingDeleteStage::PublishedUncertain(error)))
    }

    fn discard_unused_pending_delete(&self, candidate: &str, manifest_name: &str) {
        if let Err(cleanup_error) = remove_pending_manifest(self.tombstones.as_ref(), manifest_name)
        {
            tracing::warn!(
                cleanup_error = %EscapedLogValue::new(&cleanup_error),
                manifest = %EscapedLogPath::new(manifest_name),
                "could not remove unused deletion manifest"
            );
        }
        unregister_upload_fragment(candidate);
    }

    fn inspect_pending_delete(
        &self,
        parent: &SecureDirectory,
        tombstone_name: &str,
        source_identity: (u64, u64),
        source_metadata: &std::fs::Metadata,
    ) -> io::Result<EntryStatus> {
        use std::os::unix::fs::MetadataExt;

        #[cfg(test)]
        if let Some(kind) = self
            .next_delete_post_stage_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            return Err(io::Error::new(kind, "injected post-stage deletion failure"));
        }
        let tombstone = linux::openat2(
            self.tombstones.as_ref(),
            tombstone_name,
            linux::O_PATH | linux::O_NOFOLLOW,
        )?;
        let tombstone_metadata = tombstone.metadata()?;
        if (tombstone_metadata.dev(), tombstone_metadata.ino()) != source_identity
            || tombstone_metadata.is_dir() != source_metadata.is_dir()
            || tombstone_metadata.is_file() != source_metadata.is_file()
        {
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
            let directory = linux::openat2(
                self.tombstones.as_ref(),
                tombstone_name,
                linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
            )?;
            let mut scan = directory_scan_from_file(directory, false)?;
            EntryStatus {
                kind: EntryKind::Directory,
                directory_non_empty: scan.entries.next().is_some(),
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "deletion target is not a regular file or directory",
            ));
        };
        // The private destination must be durable before the visible source
        // removal. On failure, restore through the manifest. Only a verified,
        // durable restore can be reported as the original retryable error;
        // every ambiguous cleanup remains an uncertain staged mutation.
        self.tombstones.sync_all()?;
        parent.directory.sync_all()?;
        Ok(status)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_delete_staging_rename_after_success(&self, kind: io::ErrorKind) {
        *self
            .next_delete_staging_rename_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_delete_staging_identity_probes(
        &self,
        kind: io::ErrorKind,
        count: usize,
    ) {
        assert!(count > 0, "identity probe failure count must be positive");
        *self
            .next_delete_staging_identity_probe_errors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((kind, count));
    }

    fn delete_staging_identity_state(
        &self,
        directory: &std::fs::File,
        name: &str,
        expected: (u64, u64),
        kind: EntryKind,
    ) -> io::Result<EntryIdentityState> {
        #[cfg(test)]
        {
            let mut failure = self
                .next_delete_staging_identity_probe_errors
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if failure.is_some() {
                let (error_kind, exhausted) = {
                    let (error_kind, remaining) = failure
                        .as_mut()
                        .expect("identity probe fault disappeared while locked");
                    *remaining -= 1;
                    (*error_kind, *remaining == 0)
                };
                if exhausted {
                    *failure = None;
                }
                return Err(io::Error::new(
                    error_kind,
                    "injected delete-staging identity probe failure",
                ));
            }
        }
        entry_identity_state(directory, name, expected, kind)
    }

    #[allow(clippy::too_many_arguments)]
    fn reconcile_failed_delete_stage(
        &self,
        original_error: io::Error,
        pending_name: &str,
        manifest_name: &str,
        parent: &std::fs::File,
        original_name: &str,
        original_path: &str,
        source_identity: (u64, u64),
        source_kind: EntryKind,
    ) -> io::Result<DeleteStageOutcome> {
        #[cfg(test)]
        let rollback = if let Some(kind) = self
            .next_delete_rollback_rename_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            Err(io::Error::new(
                kind,
                "injected delete rollback rename failure before mutation",
            ))
        } else {
            linux::rename_noreplace_between(
                self.tombstones.as_ref(),
                pending_name,
                parent,
                original_name,
            )
        };
        #[cfg(not(test))]
        let rollback = linux::rename_noreplace_between(
            self.tombstones.as_ref(),
            pending_name,
            parent,
            original_name,
        );
        #[cfg(test)]
        let rollback = inject_error_after_successful_rename(
            rollback,
            self.next_delete_rollback_rename_response_loss.as_ref(),
        );

        let source_state =
            entry_identity_state(parent, original_name, source_identity, source_kind);
        let pending_state = entry_identity_state(
            self.tombstones.as_ref(),
            pending_name,
            source_identity,
            source_kind,
        );
        let parent_sync = self.sync_delete_rollback_parent(parent);
        let staging_sync = self.tombstones.sync_all();
        let restored = matches!(&source_state, Ok(EntryIdentityState::Expected))
            && matches!(&pending_state, Ok(EntryIdentityState::Missing));
        if restored && parent_sync.is_ok() && staging_sync.is_ok() {
            match remove_pending_manifest(self.tombstones.as_ref(), manifest_name) {
                Ok(()) => {
                    unregister_upload_fragment(pending_name);
                    return Err(original_error);
                }
                Err(manifest_error) => {
                    let error = uncertain_delete_rollback_error(
                        &original_error,
                        &rollback,
                        &source_state,
                        &pending_state,
                        &parent_sync,
                        &staging_sync,
                        Some(&manifest_error),
                    );
                    tracing::error!(
                        error = %EscapedLogValue::new(&error),
                        recovery_entry = %EscapedLogPath::new(&pending_name),
                        manifest = %EscapedLogPath::new(&manifest_name),
                        original = %EscapedLogPath::new(&original_path),
                        "delete staging rollback manifest cleanup is uncertain"
                    );
                    return Ok(DeleteStageOutcome::PublishedUncertain {
                        original_path: original_path.to_string(),
                        kind: source_kind,
                        error,
                    });
                }
            }
        }

        let error = uncertain_delete_rollback_error(
            &original_error,
            &rollback,
            &source_state,
            &pending_state,
            &parent_sync,
            &staging_sync,
            None,
        );
        tracing::error!(
            error = %EscapedLogValue::new(&error),
            recovery_entry = %EscapedLogPath::new(&pending_name),
            manifest = %EscapedLogPath::new(&manifest_name),
            original = %EscapedLogPath::new(&original_path),
            "delete staging rollback is visible or ambiguous; recovery metadata was preserved"
        );
        Ok(DeleteStageOutcome::PublishedUncertain {
            original_path: original_path.to_string(),
            kind: source_kind,
            error,
        })
    }

    fn sync_delete_rollback_parent(&self, parent: &std::fs::File) -> io::Result<()> {
        #[cfg(test)]
        if let Some(kind) = self
            .next_delete_rollback_parent_sync_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            return Err(io::Error::new(
                kind,
                "injected delete rollback parent sync failure",
            ));
        }
        parent.sync_all()
    }

    #[cfg(test)]
    pub(crate) fn fail_next_delete_post_stage(&self, kind: io::ErrorKind) {
        *self
            .next_delete_post_stage_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_delete_rollback_rename_before_mutation(&self, kind: io::ErrorKind) {
        *self
            .next_delete_rollback_rename_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_delete_rollback_rename_after_success(&self, kind: io::ErrorKind) {
        *self
            .next_delete_rollback_rename_response_loss
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_delete_rollback_parent_sync(&self, kind: io::ErrorKind) {
        *self
            .next_delete_rollback_parent_sync_error
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
    pub(crate) fn fail_next_delete_commit_sync(&self, kind: io::ErrorKind) {
        *self
            .next_delete_commit_sync_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }
}

impl StagedDelete {
    pub fn original_path(&self) -> &str {
        &self.original_path
    }

    pub fn status(&self) -> &EntryStatus {
        &self.status
    }

    pub fn commit(self, allow_recursive: bool) -> io::Result<PendingDeleteCommit> {
        match self.commit_with_outcome(allow_recursive)? {
            DeleteCommitStageOutcome::Ready(committed) => Ok(committed),
            DeleteCommitStageOutcome::PublishedUncertain { error, .. } => Err(error),
        }
    }

    pub(crate) fn commit_with_outcome(
        mut self,
        allow_recursive: bool,
    ) -> io::Result<DeleteCommitStageOutcome> {
        if let Err(error) = self.confirm_empty_only_delete(allow_recursive) {
            return self.rollback_commit_failure(error);
        }

        // Allocate every handle needed by the success path while rollback is
        // still possible. Descriptor exhaustion must not become a post-commit
        // error after the visible source has disappeared.
        let pending_staging = match self.staging.try_clone() {
            Ok(staging) => staging,
            Err(error) => return self.rollback_commit_failure(error),
        };
        let (committed_tombstone, operation_name) = match self.promote_for_cleanup(allow_recursive)
        {
            Ok(committed) => committed,
            Err(error) => return self.rollback_commit_failure(error),
        };
        self.committed = true;
        if let Err(error) = remove_pending_manifest(&self.staging, &self.manifest_name) {
            // The Moved journal is the authoritative recovery record from this
            // point onward. A stale pending manifest is harmless and startup
            // removes it once the now-renamed pending entry is absent.
            tracing::warn!(
                error = %EscapedLogValue::new(&error),
                manifest = %EscapedLogPath::new(&self.manifest_name),
                "could not remove superseded deletion manifest"
            );
        }
        #[cfg(test)]
        if let Some(hook) = self.after_promotion_hook.take() {
            hook();
        }
        if self.status.kind == EntryKind::Directory && allow_recursive {
            return Ok(DeleteCommitStageOutcome::Ready(PendingDeleteCommit {
                staging: pending_staging,
                operation_name,
                outcome: DeleteCommitOutcome {
                    cleanup_pending: true,
                    tombstone_path: Some(committed_tombstone),
                },
                active_key: self.active_key.take(),
                _storage_instance_lock: self._storage_instance_lock.clone(),
            }));
        }
        let removal = match self.status.kind {
            EntryKind::File => linux::unlink(&self.staging, OsStr::new(&self.tombstone_name)),
            EntryKind::Directory => linux::rmdir(&self.staging, OsStr::new(&self.tombstone_name)),
        };
        if let Err(error) = removal {
            if self.status.kind == EntryKind::Directory && !allow_recursive {
                let identity_state = match self.tombstone_identity_state() {
                    Ok(state) => state,
                    Err(probe_error) => {
                        return Ok(self.published_uncertain(true, probe_error));
                    }
                };
                match identity_state {
                    EntryIdentityState::Missing => {
                        // Some remote filesystems can report a lost response
                        // after rmdir executed. Only an explicit missing entry
                        // proves that no object remains eligible for cleanup.
                        if let Err(sync_error) = self.sync_committed_delete() {
                            return Ok(self.published_uncertain(false, sync_error));
                        }
                        return Ok(DeleteCommitStageOutcome::Ready(PendingDeleteCommit {
                            staging: pending_staging,
                            operation_name,
                            outcome: DeleteCommitOutcome {
                                cleanup_pending: false,
                                tombstone_path: None,
                            },
                            active_key: self.active_key.take(),
                            _storage_instance_lock: self._storage_instance_lock.clone(),
                        }));
                    }
                    EntryIdentityState::Expected => {}
                    EntryIdentityState::Replaced => {
                        return Ok(self.published_uncertain(
                            true,
                            io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                "empty-only deletion tombstone was replaced",
                            ),
                        ));
                    }
                }
                let became_non_empty = self.staged_directory_non_empty().unwrap_or(false);
                match self.rollback() {
                    Ok(()) => {
                        self.committed = true;
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
                        tracing::error!(
                            rollback_error = %EscapedLogValue::new(&rollback_error),
                            tombstone = %EscapedLogPath::new(&self.tombstone_path),
                            "could not restore an empty-only deletion after a concurrent writer added content; recovery intent was preserved"
                        );
                        return Ok(self.published_uncertain(true, rollback_error));
                    }
                }
            }
            tracing::warn!(
                error = %EscapedLogValue::new(&error),
                tombstone = %EscapedLogPath::new(&self.tombstone_path),
                "deletion tombstone cleanup deferred"
            );
            return Ok(DeleteCommitStageOutcome::Ready(PendingDeleteCommit {
                staging: pending_staging,
                operation_name,
                outcome: DeleteCommitOutcome {
                    cleanup_pending: true,
                    tombstone_path: Some(committed_tombstone),
                },
                active_key: self.active_key.take(),
                _storage_instance_lock: self._storage_instance_lock.clone(),
            }));
        }
        if let Err(error) = self.sync_committed_delete() {
            return Ok(self.published_uncertain(false, error));
        }
        Ok(DeleteCommitStageOutcome::Ready(PendingDeleteCommit {
            staging: pending_staging,
            operation_name,
            outcome: DeleteCommitOutcome {
                cleanup_pending: false,
                tombstone_path: None,
            },
            active_key: self.active_key.take(),
            _storage_instance_lock: self._storage_instance_lock.clone(),
        }))
    }

    fn confirm_empty_only_delete(&self, allow_recursive: bool) -> io::Result<()> {
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
        Ok(())
    }

    fn rollback_commit_failure(mut self, error: io::Error) -> io::Result<DeleteCommitStageOutcome> {
        match self.rollback() {
            Ok(()) => {
                self.committed = true;
                self.release_active();
                Err(error)
            }
            Err(rollback_error) => {
                tracing::error!(
                    error = %EscapedLogValue::new(&error),
                    rollback_error = %EscapedLogValue::new(&rollback_error),
                    path = %EscapedLogPath::new(&self.original_path),
                    "delete commit failed and its namespace rollback is uncertain"
                );
                Ok(self.published_uncertain(
                    true,
                    io::Error::new(
                        rollback_error.kind(),
                        format!(
                            "delete commit failed ({error}) and rollback is uncertain ({rollback_error})"
                        ),
                    ),
                ))
            }
        }
    }

    fn published_uncertain(
        &mut self,
        cleanup_pending: bool,
        error: io::Error,
    ) -> DeleteCommitStageOutcome {
        self.committed = true;
        self.release_active();
        DeleteCommitStageOutcome::PublishedUncertain {
            cleanup_pending,
            error,
        }
    }

    fn sync_committed_delete(&self) -> io::Result<()> {
        #[cfg(test)]
        if let Some(kind) = self
            .next_commit_sync_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            return Err(io::Error::new(
                kind,
                "injected committed-delete sync failure",
            ));
        }
        self.staging.sync_all()
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
            tracing::warn!(
                error = %EscapedLogValue::new(&error),
                manifest = %EscapedLogPath::new(&self.manifest_name),
                "could not remove durable rollback manifest"
            );
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
                        tracing::warn!(
                            error = %EscapedLogValue::new(&error),
                            tombstone = %EscapedLogPath::new(&committed_name),
                            "committed deletion rename returned an error after the pending entry moved; continuing with verified identity"
                        );
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

impl Drop for StagedDelete {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(error) = self.rollback() {
                // Pending names are deliberately excluded from every automatic
                // cleanup pass. If a co-writer occupied the original name, both
                // objects survive and an operator can recover the pending entry.
                tracing::error!(
                    error = %EscapedLogValue::new(&error),
                    recovery_entry = %EscapedLogPath::new(&self.tombstone_path),
                    original = %EscapedLogPath::new(&self.original_path),
                    "could not roll back staged deletion; private recovery entry was preserved"
                );
            }
            self.release_active();
        }
    }
}
