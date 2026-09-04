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
