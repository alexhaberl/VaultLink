impl SecureRoot {
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
                        tracing::warn!(
                            from = %EscapedLogPath::new(&original_path),
                            to = %EscapedLogPath::new(&new_path),
                            "completed rename target is missing; old-path replacements were preserved"
                        );
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
        Ok(rename_recovery_outcome(original_path, new_path, kind))
    }
}

fn rename_recovery_outcome(
    original_path: &str,
    new_path: &str,
    kind: EntryKind,
) -> FileOperationRecovery {
    FileOperationRecovery::Rename {
        original_path: original_path.to_string(),
        new_path: new_path.to_string(),
        is_directory: kind == EntryKind::Directory,
    }
}
