impl SecureRoot {
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
                    tracing::warn!(
                        error = %EscapedLogValue::new(&error),
                        original = %EscapedLogPath::new(original_path),
                        "delete rollback rename returned an error after restoration; continuing with verified identity"
                    );
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
