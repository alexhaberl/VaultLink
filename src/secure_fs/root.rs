#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryIdentityState {
    Expected,
    Missing,
    Replaced,
}

fn open_configured_root(
    path: &Path,
    locked_root: Option<File>,
) -> io::Result<(PathBuf, Arc<File>)> {
    let display_root = path.canonicalize()?;
    let path_directory = File::open(&display_root)?;
    if !path_directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage root is not a directory",
        ));
    }
    let directory = if let Some(locked_root) = locked_root {
        let locked_metadata = locked_root.metadata()?;
        let path_metadata = path_directory.metadata()?;
        if !locked_metadata.is_dir()
            || (locked_metadata.dev(), locked_metadata.ino())
                != (path_metadata.dev(), path_metadata.ino())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "root_mount_path changed after mount validation and lock acquisition",
            ));
        }
        locked_root
    } else {
        path_directory
    };
    Ok((display_root, Arc::new(directory)))
}

#[allow(clippy::too_many_arguments)]
fn open_configured_internal(
    display_root: &Path,
    directory: &File,
    internal_directory: Option<&Path>,
    require_preprovisioned_internal: bool,
    forbid_user_symlinks: bool,
    locked_internal: Option<File>,
) -> io::Result<Arc<File>> {
    let internal_path = internal_directory
        .map(Path::to_path_buf)
        .unwrap_or_else(|| display_root.join(INTERNAL_DIRECTORY_NAME));
    let internal_parent = internal_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "VaultLink internal storage needs a parent directory",
        )
    })?;
    let internal_name = internal_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "VaultLink internal storage needs a UTF-8 directory name",
            )
        })?;
    let internal_parent = File::open(internal_parent.canonicalize()?)?;
    // The lock acquisition already created/opened this directory. During the
    // capability handoff, never create a replacement namespace before proving
    // that the configured entry still names the locked inode.
    let create_internal = !require_preprovisioned_internal && locked_internal.is_none();
    let path_internal = open_private_directory(&internal_parent, internal_name, create_internal)?;
    let internal = if let Some(locked_internal) = locked_internal {
        let locked_metadata = locked_internal.metadata()?;
        let path_metadata = path_internal.metadata()?;
        if !locked_metadata.is_dir()
            || (locked_metadata.dev(), locked_metadata.ino())
                != (path_metadata.dev(), path_metadata.ino())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "internal_directory changed after the process-lifetime lock was acquired",
            ));
        }
        locked_internal
    } else {
        path_internal
    };
    let internal = Arc::new(internal);
    let canonical_internal = internal_path.canonicalize()?;
    let nested_reserved_internal = canonical_internal.parent() == Some(display_root)
        && canonical_internal
            .file_name()
            .is_some_and(crate::path_security::is_internal_storage_name);
    if require_preprovisioned_internal
        && (display_root.starts_with(&canonical_internal)
            || (canonical_internal.starts_with(display_root)
                && !(forbid_user_symlinks && nested_reserved_internal)))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "preprovisioned internal storage must be either outside the visible root or its direct reserved child with symlink traversal disabled",
        ));
    }
    if internal.metadata()?.dev() != directory.metadata()?.dev() {
        return Err(io::Error::new(
            io::ErrorKind::CrossesDevices,
            "VaultLink internal storage and user-visible root must share one filesystem",
        ));
    }
    Ok(internal)
}

#[allow(clippy::too_many_arguments)]
fn build_secure_root(
    display_root: PathBuf,
    directory: Arc<File>,
    uploads: Arc<File>,
    tombstones: Arc<File>,
    forbid_user_symlinks: bool,
    allow_replace: bool,
    storage_instance_lock: Option<Arc<crate::StorageInstanceLock>>,
) -> SecureRoot {
    #[cfg(test)]
    let next_create_directory_sync_error = Arc::new(Mutex::new(None));
    #[cfg(test)]
    let next_create_directory_mkdir_error = Arc::new(Mutex::new(None));
    #[cfg(test)]
    let next_create_directory_probe_error = Arc::new(Mutex::new(None));
    #[cfg(test)]
    let next_upload_publication_rename_error = Arc::new(Mutex::new(None));
    #[cfg(test)]
    let next_upload_publication_identity_probe_errors = Arc::new(Mutex::new(None));
    #[cfg(test)]
    let after_directory_tree_create_hook = Arc::new(Mutex::new(None));
    SecureRoot {
        display_root,
        root: SecureDirectory {
            directory,
            staging: uploads,
            forbid_symlinks: forbid_user_symlinks,
            allow_replace,
            _storage_instance_lock: storage_instance_lock.clone(),
            #[cfg(test)]
            next_create_directory_sync_error: next_create_directory_sync_error.clone(),
            #[cfg(test)]
            next_create_directory_mkdir_error: next_create_directory_mkdir_error.clone(),
            #[cfg(test)]
            next_create_directory_probe_error: next_create_directory_probe_error.clone(),
            #[cfg(test)]
            next_upload_publication_rename_error: next_upload_publication_rename_error.clone(),
            #[cfg(test)]
            next_upload_publication_identity_probe_errors:
                next_upload_publication_identity_probe_errors.clone(),
            #[cfg(test)]
            after_directory_tree_create_hook,
        },
        tombstones,
        _storage_instance_lock: storage_instance_lock,
        #[cfg(test)]
        next_delete_staging_rename_error: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        next_delete_staging_identity_probe_errors: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        next_delete_post_stage_error: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        next_delete_rollback_rename_error: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        next_delete_rollback_rename_response_loss: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        next_delete_rollback_parent_sync_error: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        next_delete_promotion_rename_error: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        next_delete_identity_probe_error: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        next_rename_parent_sync_error: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        next_delete_commit_sync_error: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        before_rename_hook: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        next_cleanup_start_errors: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        next_cleanup_batch_error: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        next_create_directory_sync_error,
        #[cfg(test)]
        next_create_directory_mkdir_error,
        #[cfg(test)]
        next_create_directory_probe_error,
        #[cfg(test)]
        next_upload_publication_rename_error,
        #[cfg(test)]
        next_upload_publication_identity_probe_errors,
        #[cfg(test)]
        before_cleanup_batch_hook: Arc::new(Mutex::new(None)),
    }
}

impl SecureRoot {
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_configured(path, None, false, false)
    }

    pub fn open_configured(
        path: &Path,
        internal_directory: Option<&Path>,
        require_preprovisioned_internal: bool,
        forbid_user_symlinks: bool,
    ) -> io::Result<Self> {
        Self::open_configured_inner(
            path,
            internal_directory,
            require_preprovisioned_internal,
            forbid_user_symlinks,
            !forbid_user_symlinks,
            None,
        )
    }

    /// Opens storage with the exact root and private-directory capabilities on
    /// which the caller already validated the mount and acquired the
    /// process-lifetime lock. Configured paths are reopened only to verify
    /// device/inode identity before any mutation probe or recovery; all
    /// subsequent storage operations use the handed-off descriptors.
    pub(crate) fn open_configured_with_locked_internal(
        path: &Path,
        internal_directory: Option<&Path>,
        require_preprovisioned_internal: bool,
        forbid_user_symlinks: bool,
        allow_replace: bool,
        storage_instance_lock: Arc<crate::StorageInstanceLock>,
    ) -> io::Result<Self> {
        Self::open_configured_inner(
            path,
            internal_directory,
            require_preprovisioned_internal,
            forbid_user_symlinks,
            allow_replace,
            Some(storage_instance_lock),
        )
    }

    fn open_configured_inner(
        path: &Path,
        internal_directory: Option<&Path>,
        require_preprovisioned_internal: bool,
        forbid_user_symlinks: bool,
        allow_replace: bool,
        storage_instance_lock: Option<Arc<crate::StorageInstanceLock>>,
    ) -> io::Result<Self> {
        let locked_root = storage_instance_lock
            .as_ref()
            .map(|lock| lock.root.try_clone())
            .transpose()?;
        let locked_internal = storage_instance_lock
            .as_ref()
            .map(|lock| lock.internal.try_clone())
            .transpose()?;
        let (display_root, directory) = open_configured_root(path, locked_root)?;
        // Probe the required kernel API at startup and fail with a useful error.
        linux::openat2(
            directory.as_ref(),
            ".",
            linux::O_RDONLY | linux::O_DIRECTORY,
        )?;
        let internal = open_configured_internal(
            &display_root,
            directory.as_ref(),
            internal_directory,
            require_preprovisioned_internal,
            forbid_user_symlinks,
            locked_internal,
        )?;
        let uploads = Arc::new(open_private_directory(
            internal.as_ref(),
            UPLOAD_STAGING_DIRECTORY_NAME,
            !require_preprovisioned_internal,
        )?);
        let tombstones = Arc::new(open_private_directory(
            internal.as_ref(),
            TOMBSTONE_STAGING_DIRECTORY_NAME,
            !require_preprovisioned_internal,
        )?);
        probe_storage_mutations(uploads.as_ref(), tombstones.as_ref())?;
        let secure_root = build_secure_root(
            display_root,
            directory,
            uploads,
            tombstones,
            forbid_user_symlinks,
            allow_replace,
            storage_instance_lock,
        );
        secure_root.remove_incomplete_file_operation_writes()?;
        let pending_operations = secure_root.pending_file_operations()?;
        secure_root.recover_pending_deletions(&pending_operations)?;
        Ok(secure_root)
    }

    pub fn create_directory(
        &self,
        parent: &str,
        name: &str,
    ) -> io::Result<(String, PublishOutcome)> {
        let parent = normalized(parent)?;
        let name = path_security::safe_admin_filename(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid directory name"))?;
        let outcome = self
            .root
            .bind_directory(&parent)?
            .create_directory_with_outcome(name)?;
        Ok((join_relative(&parent, name), outcome))
    }

    #[cfg(test)]
    pub(crate) fn fail_next_create_directory_sync(&self, kind: io::ErrorKind) {
        *self
            .next_create_directory_sync_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_create_directory_mkdir_after_success(&self, kind: io::ErrorKind) {
        *self
            .next_create_directory_mkdir_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_create_directory_probe(&self, kind: io::ErrorKind) {
        *self
            .next_create_directory_probe_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_upload_publication_rename_after_success(&self, kind: io::ErrorKind) {
        *self
            .next_upload_publication_rename_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_upload_publication_identity_probes(
        &self,
        kind: io::ErrorKind,
        count: usize,
    ) {
        assert!(count > 0, "identity probe failure count must be positive");
        *self
            .next_upload_publication_identity_probe_errors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((kind, count));
    }

    #[cfg(test)]
    pub(crate) fn after_next_directory_tree_create(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .root
            .after_directory_tree_create_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Box::new(hook));
    }
}
