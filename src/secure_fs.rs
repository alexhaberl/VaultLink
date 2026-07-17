//! Descriptor-relative storage access. Linux production builds use `openat2(2)`
//! so a path cannot escape the configured root between validation and use.

mod capability;
mod identity;
mod journal;
mod private_entries;
mod recovery;
mod staging;
mod upload;

use capability::{directory_scan_from_file, linux};
#[cfg(test)]
use journal::{replace_delete_operation_phase, replace_file_operation, write_file_operation};
use private_entries::ActiveUploadFragmentKey;
#[cfg(test)]
use private_entries::{active_upload_fragment_guard, unregister_upload_fragment};
pub use private_entries::{is_upload_fragment_name, upload_fragment_name};
#[cfg(test)]
use recovery::{rebase_cleanup_directory, start_cleanup_from_directory};
pub use upload::{PendingUpload, PublishOutcome};

use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::SystemTime,
};

use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::path_security;

const DELETION_TOMBSTONE_PREFIX: &str = ".vaultlink-delete-";
const DELETION_TOMBSTONE_SUFFIX: &str = ".tombstone";
const DELETION_TOMBSTONE_TOKEN_LENGTH: usize = 24;
const CLEANUP_SEGMENT_PREFIX: &str = ".vaultlink-cleanup-segment-";
const DELETION_PENDING_PREFIX: &str = ".vaultlink-delete-pending-";
const DELETION_PENDING_SUFFIX: &str = ".pending";
const DELETION_MANIFEST_SUFFIX: &str = ".manifest";
const FILE_OPERATION_PREFIX: &str = ".vaultlink-operation-";
const FILE_OPERATION_SUFFIX: &str = ".json";
const FILE_OPERATION_TOKEN_LENGTH: usize = 24;
const INTERNAL_DIRECTORY_NAME: &str = path_security::INTERNAL_STORAGE_DIRECTORY_NAME;
const UPLOAD_STAGING_DIRECTORY_NAME: &str = "uploads";
const TOMBSTONE_STAGING_DIRECTORY_NAME: &str = "tombstones";
// Each recursive level retains a directory capability, a ReadDir cursor and,
// except for the root, a parent capability. Keep ample headroom for the rest of
// the process even with a comparatively small RLIMIT_NOFILE.
const MAX_CLEANUP_DIRECTORY_STACK: usize = 32;
// The set is defense in depth against revisiting a directory identity while a
// private tree is being mutated. Bound it independently from batch size because
// a cleanup cursor intentionally survives across many batches.
const MAX_CLEANUP_VISITED_DIRECTORIES: usize = 16_384;

#[cfg(test)]
type TestOnceHook = Box<dyn FnOnce() + Send + 'static>;

pub fn deletion_tombstone_name() -> String {
    format!(
        "{DELETION_TOMBSTONE_PREFIX}{}{DELETION_TOMBSTONE_SUFFIX}",
        crate::auth::random_token(18)
    )
}

fn cleanup_segment_name() -> String {
    format!("{CLEANUP_SEGMENT_PREFIX}{}", crate::auth::random_token(18))
}

fn deletion_pending_name() -> String {
    format!(
        "{DELETION_PENDING_PREFIX}{}{DELETION_PENDING_SUFFIX}",
        crate::auth::random_token(18)
    )
}

fn is_deletion_pending_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(token) = name
        .strip_prefix(DELETION_PENDING_PREFIX)
        .and_then(|name| name.strip_suffix(DELETION_PENDING_SUFFIX))
    else {
        return false;
    };
    token.len() == DELETION_TOMBSTONE_TOKEN_LENGTH
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn deletion_manifest_name(pending_name: &str) -> String {
    format!("{pending_name}{DELETION_MANIFEST_SUFFIX}")
}

fn deletion_pending_from_manifest_name(name: &OsStr) -> Option<&str> {
    let name = name.to_str()?;
    let pending_name = name.strip_suffix(DELETION_MANIFEST_SUFFIX)?;
    is_deletion_pending_name(OsStr::new(pending_name)).then_some(pending_name)
}

fn file_operation_name() -> String {
    format!(
        "{FILE_OPERATION_PREFIX}{}{FILE_OPERATION_SUFFIX}",
        crate::auth::random_token(18)
    )
}

fn is_file_operation_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(token) = name
        .strip_prefix(FILE_OPERATION_PREFIX)
        .and_then(|name| name.strip_suffix(FILE_OPERATION_SUFFIX))
    else {
        return false;
    };
    token.len() == FILE_OPERATION_TOKEN_LENGTH
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn is_file_operation_temporary_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(operation_name) = name.strip_suffix(".pending") else {
        return false;
    };
    is_file_operation_name(OsStr::new(operation_name))
}

pub fn is_deletion_tombstone_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(token) = name
        .strip_prefix(DELETION_TOMBSTONE_PREFIX)
        .and_then(|name| name.strip_suffix(DELETION_TOMBSTONE_SUFFIX))
    else {
        return false;
    };
    token.len() == DELETION_TOMBSTONE_TOKEN_LENGTH
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryStatus {
    pub kind: EntryKind,
    pub directory_non_empty: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteCommitOutcome {
    pub cleanup_pending: bool,
    pub tombstone_path: Option<String>,
}

#[derive(Clone)]
pub struct SecureRoot {
    display_root: PathBuf,
    root: SecureDirectory,
    tombstones: Arc<File>,
    // Configured production roots inherit the process-lifetime lock. Plain
    // test/library roots opened without AppState intentionally have no lock.
    _storage_instance_lock: Option<Arc<crate::StorageInstanceLock>>,
    #[cfg(test)]
    next_delete_staging_rename_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_delete_promotion_rename_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_delete_identity_probe_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    before_rename_hook: Arc<Mutex<Option<TestOnceHook>>>,
    #[cfg(test)]
    next_cleanup_start_errors: Arc<Mutex<Option<(io::ErrorKind, usize)>>>,
    #[cfg(test)]
    next_cleanup_batch_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_create_directory_sync_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    before_cleanup_batch_hook: Arc<Mutex<Option<TestOnceHook>>>,
}

/// A descriptor/path capability whose relative operations cannot resolve above this directory.
#[derive(Clone)]
pub struct SecureDirectory {
    directory: Arc<File>,
    staging: Arc<File>,
    forbid_symlinks: bool,
    allow_replace: bool,
    _storage_instance_lock: Option<Arc<crate::StorageInstanceLock>>,
    #[cfg(test)]
    next_create_directory_sync_error: Arc<Mutex<Option<io::ErrorKind>>>,
}

/// An already-opened regular file bound to the scope that authorized it.
pub struct SecureFile {
    file: File,
}

#[derive(Debug)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub len: u64,
    pub modified: Option<SystemTime>,
}

/// One raw directory item. Filtered items still consume scan budget, which keeps
/// callers bounded even when a directory contains only symlinks, special files,
/// non-UTF-8 names, or private upload fragments.
pub enum DirectoryScanItem {
    Visible(Entry),
    Filtered,
}

/// A continuation-preserving directory iterator. Unlike offset pagination, it
/// never rescans entries that were already consumed.
pub struct DirectoryScan {
    entries: std::fs::ReadDir,
    directory: File,
    strict_mount_boundary: bool,
}

#[derive(Debug, Default)]
pub struct DirectoryScanBatch {
    pub entries: Vec<Entry>,
    pub scanned: usize,
    pub complete: bool,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct UploadFragmentCleanupBatch {
    pub scanned: usize,
    pub removed: usize,
    pub failed: usize,
    pub complete: bool,
}

/// Stateful recursive cleanup. Keep this value between bounded batches so a
/// large directory continues at its current cursor instead of restarting at the
/// first entry on every pass.
pub struct UploadFragmentCleanup {
    directories: Vec<CleanupDirectory>,
    visited: HashSet<(u64, u64)>,
    max_directory_stack: usize,
    max_visited_directories: usize,
    operation_staging: Option<File>,
    // Cleanup cursors move into spawn_blocking independently of AppState.
    // Retain the storage lock until the last batch has actually returned.
    _storage_instance_lock: Option<Arc<crate::StorageInstanceLock>>,
    #[cfg(test)]
    next_batch_error: Option<Arc<Mutex<Option<io::ErrorKind>>>>,
    #[cfg(test)]
    before_batch_hook: Option<Arc<Mutex<Option<TestOnceHook>>>>,
}

struct CleanupDirectory {
    directory: File,
    entries: std::fs::ReadDir,
    removed_in_pass: bool,
    policy: CleanupPolicy,
    remove_from: Option<(File, OsString)>,
    deletion_root: Option<Arc<File>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupPolicy {
    UploadFragments,
    TombstoneRoot,
    DeleteAll,
}

pub struct StagedRename {
    original_path: String,
    new_path: String,
    kind: EntryKind,
    source_identity: (u64, u64),
    committed: bool,
    parent: File,
    operation_staging: File,
    original_name: String,
    new_name: String,
    operation_name: String,
    commit_started: bool,
    _storage_instance_lock: Option<Arc<crate::StorageInstanceLock>>,
}

pub struct StagedDelete {
    original_path: String,
    tombstone_path: String,
    status: EntryStatus,
    committed: bool,
    parent: File,
    staging: File,
    original_name: String,
    tombstone_name: String,
    manifest_name: String,
    operation_name: Option<String>,
    source_identity: (u64, u64),
    active_key: Option<ActiveUploadFragmentKey>,
    _storage_instance_lock: Option<Arc<crate::StorageInstanceLock>>,
    #[cfg(test)]
    next_promotion_rename_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_identity_probe_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    after_promotion_hook: Option<TestOnceHook>,
}

pub struct PendingDeleteCommit {
    staging: File,
    operation_name: String,
    outcome: DeleteCommitOutcome,
    active_key: Option<ActiveUploadFragmentKey>,
    _storage_instance_lock: Option<Arc<crate::StorageInstanceLock>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DurableEntryKind {
    File,
    Directory,
}

impl From<EntryKind> for DurableEntryKind {
    fn from(value: EntryKind) -> Self {
        match value {
            EntryKind::File => Self::File,
            EntryKind::Directory => Self::Directory,
        }
    }
}

impl From<DurableEntryKind> for EntryKind {
    fn from(value: DurableEntryKind) -> Self {
        match value {
            DurableEntryKind::File => Self::File,
            DurableEntryKind::Directory => Self::Directory,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DurableRenamePhase {
    Intent,
    #[default]
    Moved,
    Rollback,
}

/// Old delete journals predate explicit phases and were only removed after the
/// database commit. Treat those as `Moved` during deserialization so upgrades
/// preserve their original forward-recovery semantics.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DurableDeletePhase {
    Intent,
    #[default]
    Moved,
    Rollback,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum DurableFileOperation {
    Rename {
        original_path: String,
        new_path: String,
        kind: DurableEntryKind,
        device: u64,
        inode: u64,
        #[serde(default)]
        phase: DurableRenamePhase,
    },
    Delete {
        original_path: String,
        kind: DurableEntryKind,
        device: u64,
        inode: u64,
        pending_name: String,
        tombstone_name: String,
        allow_recursive: bool,
        #[serde(default)]
        phase: DurableDeletePhase,
    },
}

#[derive(Debug)]
struct FileOperationWriteError {
    error: io::Error,
    published_name: Option<String>,
}

impl FileOperationWriteError {
    fn before_publish(error: io::Error) -> Self {
        Self {
            error,
            published_name: None,
        }
    }

    fn into_io(self) -> io::Error {
        self.error
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingFileOperation {
    journal_name: String,
    operation: DurableFileOperation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FileOperationRecovery {
    Rename {
        original_path: String,
        new_path: String,
        is_directory: bool,
    },
    Delete {
        original_path: String,
        is_directory: bool,
        tombstone_path: Option<String>,
    },
    Cancelled,
}

fn open_private_directory(parent: &File, name: &str, create: bool) -> io::Result<File> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mut created = false;
    if create {
        match linux::mkdir(parent, name) {
            Ok(()) => created = true,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    if created {
        parent.sync_all()?;
    }
    let directory = linux::openat2(
        parent,
        name,
        linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
    )?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.dev() != parent.metadata()?.dev() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VaultLink internal storage must be a directory on the storage-root filesystem",
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VaultLink internal storage must not grant group or other mode permissions",
        ));
    }
    Ok(directory)
}

fn probe_storage_mutations(source: &File, destination: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if source.metadata()?.dev() != destination.metadata()?.dev() {
        return Err(io::Error::new(
            io::ErrorKind::CrossesDevices,
            "VaultLink internal staging directories must share one filesystem",
        ));
    }
    let first = upload_fragment_name();
    let second = deletion_tombstone_name();
    let result = (|| {
        let first_file = linux::openat2(
            source,
            &first,
            linux::O_WRONLY | linux::O_CREAT | linux::O_EXCL,
        )?;
        let first_identity = {
            let metadata = first_file.metadata()?;
            (metadata.dev(), metadata.ino())
        };
        first_file.sync_all()?;
        let second_file = linux::openat2(
            destination,
            &second,
            linux::O_WRONLY | linux::O_CREAT | linux::O_EXCL,
        )?;
        let second_identity = {
            let metadata = second_file.metadata()?;
            (metadata.dev(), metadata.ino())
        };
        if second_identity == first_identity {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "storage backend does not expose unique file identities",
            ));
        }
        second_file.sync_all()?;
        drop(first_file);
        drop(second_file);

        match linux::rename_noreplace_between(source, &first, destination, &second) {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Ok(()) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "storage backend ignored RENAME_NOREPLACE",
                ));
            }
            Err(error) => return Err(error),
        }
        linux::unlink(destination, &second)?;
        linux::rename_noreplace_between(source, &first, destination, &second)?;
        let moved = linux::openat2(destination, &second, linux::O_PATH | linux::O_NOFOLLOW)?;
        let moved_metadata = moved.metadata()?;
        if !moved_metadata.is_file()
            || (moved_metadata.dev(), moved_metadata.ino()) != first_identity
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "storage backend does not preserve stable file identity across rename",
            ));
        }
        source.sync_all()?;
        destination.sync_all()?;

        let replacement = linux::openat2(
            source,
            &first,
            linux::O_WRONLY | linux::O_CREAT | linux::O_EXCL,
        )?;
        let replacement_identity = {
            let metadata = replacement.metadata()?;
            (metadata.dev(), metadata.ino())
        };
        replacement.sync_all()?;
        drop(replacement);
        linux::rename_replace_between(source, &first, destination, &second)?;
        let replaced = linux::openat2(destination, &second, linux::O_PATH | linux::O_NOFOLLOW)?;
        let replaced_metadata = replaced.metadata()?;
        if !replaced_metadata.is_file()
            || (replaced_metadata.dev(), replaced_metadata.ino()) != replacement_identity
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "storage backend does not preserve replacement identity across rename",
            ));
        }
        source.sync_all()?;
        destination.sync_all()
    })();
    let _ = linux::unlink(source, &first);
    let _ = linux::unlink(destination, &second);
    let _ = source.sync_all();
    let _ = destination.sync_all();
    result.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("storage backend failed required atomic mutation probe: {error}"),
        )
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryIdentityState {
    Expected,
    Missing,
    Replaced,
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
        let directory = Arc::new(directory);
        // Probe the required kernel API at startup and fail with a useful error.
        linux::openat2(
            directory.as_ref(),
            ".",
            linux::O_RDONLY | linux::O_DIRECTORY,
        )?;
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
        // The lock acquisition already created/opened this directory. During
        // the capability handoff, never create a replacement namespace before
        // proving that the configured entry still names the locked inode.
        let create_internal = !require_preprovisioned_internal && locked_internal.is_none();
        let path_internal =
            open_private_directory(&internal_parent, internal_name, create_internal)?;
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
        let nested_reserved_internal = canonical_internal.parent() == Some(display_root.as_path())
            && canonical_internal
                .file_name()
                .is_some_and(crate::path_security::is_internal_storage_name);
        if require_preprovisioned_internal
            && (display_root.starts_with(&canonical_internal)
                || (canonical_internal.starts_with(&display_root)
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
        #[cfg(test)]
        let next_create_directory_sync_error = Arc::new(Mutex::new(None));
        let secure_root = Self {
            display_root,
            root: SecureDirectory {
                directory,
                staging: uploads,
                forbid_symlinks: forbid_user_symlinks,
                allow_replace,
                _storage_instance_lock: storage_instance_lock.clone(),
                #[cfg(test)]
                next_create_directory_sync_error: next_create_directory_sync_error.clone(),
            },
            tombstones,
            _storage_instance_lock: storage_instance_lock,
            #[cfg(test)]
            next_delete_staging_rename_error: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            next_delete_promotion_rename_error: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            next_delete_identity_probe_error: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            before_rename_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            next_cleanup_start_errors: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            next_cleanup_batch_error: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            next_create_directory_sync_error,
            #[cfg(test)]
            before_cleanup_batch_hook: Arc::new(Mutex::new(None)),
        };
        secure_root.remove_incomplete_file_operation_writes()?;
        let pending_operations = secure_root.pending_file_operations()?;
        secure_root.recover_pending_deletions(&pending_operations)?;
        Ok(secure_root)
    }

    pub fn create_directory(&self, parent: &str, name: &str) -> io::Result<String> {
        let parent = normalized(parent)?;
        let name = path_security::safe_admin_filename(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid directory name"))?;
        self.root.bind_directory(&parent)?.create_directory(name)?;
        Ok(join_relative(&parent, name))
    }

    #[cfg(test)]
    fn fail_next_create_directory_sync(&self, kind: io::ErrorKind) {
        *self
            .next_create_directory_sync_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }
}

impl SecureDirectory {
    /// Creates every missing directory component below this descriptor-bound
    /// scope. Existing directories are accepted, while files and symlinks fail
    /// closed when the capability is narrowed to the next component.
    pub fn ensure_directory_tree(&self, relative: &str) -> io::Result<Vec<String>> {
        let relative = path_security::validate_relative(relative)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid directory path"))?
            .to_string_lossy()
            .replace('\\', "/");
        let mut current = self.clone();
        let mut current_path = String::new();
        let mut created = Vec::new();
        for component in relative
            .split('/')
            .filter(|component| !component.is_empty())
        {
            path_security::safe_admin_filename(component).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid directory name")
            })?;
            match current.create_directory(component) {
                Ok(()) => {
                    current_path = join_relative(&current_path, component);
                    created.push(current_path.clone());
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    current_path = join_relative(&current_path, component);
                }
                Err(error) => return Err(error),
            }
            current = current.bind_directory(component)?;
        }
        Ok(created)
    }

    fn create_directory(&self, name: &str) -> io::Result<()> {
        path_security::safe_admin_filename(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid directory name"))?;
        linux::mkdir(self.directory.as_ref(), name)?;
        #[cfg(test)]
        if let Some(kind) = self
            .next_create_directory_sync_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            return Err(io::Error::new(
                kind,
                "injected directory parent sync failure",
            ));
        }
        self.directory.sync_all()
    }

    fn rename_noreplace(&self, old: &str, new: &str) -> io::Result<()> {
        linux::rename_noreplace(self.directory.as_ref(), old, new)?;
        if let Err(error) = self.directory.sync_all() {
            tracing::warn!(%error, "renamed entry but parent sync was uncertain");
        }
        Ok(())
    }
}

fn validated(raw: &str) -> io::Result<String> {
    let path = path_security::validate_relative(raw).map_err(path_error)?;
    let value = path.to_string_lossy().replace('\\', "/");
    Ok(if value.is_empty() { ".".into() } else { value })
}

fn normalized(raw: &str) -> io::Result<String> {
    let path = path_security::validate_relative(raw).map_err(path_error)?;
    Ok(path.to_string_lossy().replace('\\', "/"))
}

fn split_parent_name(relative: &str) -> io::Result<(String, String)> {
    let relative = normalized(relative)?;
    if relative.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage root cannot be mutated",
        ));
    }
    let (parent, name) = relative
        .rsplit_once('/')
        .map_or(("", relative.as_str()), |(parent, name)| (parent, name));
    path_security::safe_admin_filename(name).map_err(path_error)?;
    Ok((parent.to_string(), name.to_string()))
}

fn split_parent_name_private(relative: &str) -> io::Result<(String, String)> {
    let relative = normalized(relative)?;
    if relative.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing entry name",
        ));
    }
    let (parent, name) = relative
        .rsplit_once('/')
        .map_or(("", relative.as_str()), |(parent, name)| (parent, name));
    path_security::safe_filename(name).map_err(path_error)?;
    Ok((parent.to_string(), name.to_string()))
}

fn join_relative(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

fn path_error(error: path_security::PathError) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, sync::Arc};

    #[test]
    fn upload_fragment_filter_is_strict() {
        let generated = upload_fragment_name();
        assert!(is_upload_fragment_name(OsStr::new(&generated)));
        for name in [
            ".vaultlink-short.part",
            ".vaultlink-AAAAAAAAAAAAAAAAAAAAAAAA.tmp",
            ".vaultlink-AAAAAAAAAAAAAAAAAAAAAAA!.part",
            "vaultlink-AAAAAAAAAAAAAAAAAAAAAAAA.part",
            ".vaultlink-AAAAAAAAAAAAAAAAAAAAAAAA.part.bak",
        ] {
            assert!(!is_upload_fragment_name(OsStr::new(name)), "{name}");
        }
    }

    #[test]
    fn private_fragment_namespace_cannot_be_published() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let mut pending = root.begin_upload("").unwrap();
        pending.take_file().unwrap().write_all(b"content").unwrap();
        assert_eq!(
            pending.publish(&upload_fragment_name()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn deletion_tombstone_filter_is_strict() {
        let generated = deletion_tombstone_name();
        assert!(is_deletion_tombstone_name(OsStr::new(&generated)));
        for name in [
            ".vaultlink-delete-short.tombstone",
            ".vaultlink-delete-AAAAAAAAAAAAAAAAAAAAAAAA.part",
            ".vaultlink-delete-AAAAAAAAAAAAAAAAAAAAAAA!.tombstone",
            "vaultlink-delete-AAAAAAAAAAAAAAAAAAAAAAAA.tombstone",
        ] {
            assert!(!is_deletion_tombstone_name(OsStr::new(name)), "{name}");
        }
    }

    #[test]
    fn admin_mutations_create_rename_rollback_and_delete_tree() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        assert_eq!(root.create_directory("", "docs").unwrap(), "docs");
        std::fs::write(directory.path().join("docs/file.txt"), b"content").unwrap();

        {
            let staged = root.stage_rename("docs/file.txt", "draft.txt").unwrap();
            assert_eq!(staged.kind(), EntryKind::File);
            assert!(directory.path().join("docs/draft.txt").exists());
        }
        assert!(directory.path().join("docs/file.txt").exists());

        root.stage_rename("docs/file.txt", "final.txt")
            .unwrap()
            .commit()
            .unwrap();
        assert!(directory.path().join("docs/final.txt").exists());
        assert!(root.stage_rename("docs/final.txt", "final.txt").is_err());
        assert!(root
            .create_directory("", &deletion_tombstone_name())
            .is_err());

        let staged = root.stage_delete("docs").unwrap();
        assert_eq!(
            staged.status(),
            &EntryStatus {
                kind: EntryKind::Directory,
                directory_non_empty: true,
            }
        );
        let outcome = staged.commit(true).unwrap().complete().unwrap();
        assert!(outcome.cleanup_pending);
        assert!(!directory.path().join("docs").exists());
        let tombstone = outcome.tombstone_path.unwrap();
        let mut cleanup = root.start_deletion_cleanup(&tombstone).unwrap();
        loop {
            let batch = cleanup.run_batch(1).unwrap();
            if batch.complete {
                break;
            }
        }
        assert!(root.list("", 0, 10).unwrap().is_empty());
    }

    #[test]
    fn directory_tree_creation_is_descriptor_bound_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let scope = root.bind_directory("").unwrap();
        assert_eq!(
            scope.ensure_directory_tree("album/2026/summer").unwrap(),
            ["album", "album/2026", "album/2026/summer"]
        );
        assert!(scope
            .ensure_directory_tree("album/2026/summer")
            .unwrap()
            .is_empty());
        std::fs::write(directory.path().join("file"), b"content").unwrap();
        assert!(scope.ensure_directory_tree("file/child").is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.path(), directory.path().join("escape")).unwrap();
            assert!(scope.ensure_directory_tree("escape/child").is_err());
            assert!(!outside.path().join("child").exists());
        }
    }

    #[test]
    fn create_directory_reports_parent_sync_uncertainty() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        root.fail_next_create_directory_sync(io::ErrorKind::Other);

        let error = root.create_directory("", "uncertain").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(directory.path().join("uncertain").is_dir());
    }

    #[test]
    fn empty_directory_delete_restores_late_external_content_instead_of_cleaning_it() {
        use std::os::fd::AsRawFd;

        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::create_dir(directory.path().join("empty")).unwrap();
        let external_writer = File::open(directory.path().join("empty")).unwrap();

        let mut staged = root.stage_delete("empty").unwrap();
        assert!(!staged.status().directory_non_empty);
        let cleanup_root = root.clone();
        staged.run_after_promotion(move || {
            std::fs::write(
                format!("/proc/self/fd/{}/late.txt", external_writer.as_raw_fd()),
                b"must survive",
            )
            .unwrap();

            // Model a generic cleanup cursor that was started before the
            // operation journal existed. The in-process active guard must keep
            // it from recursively entering the newly promoted tombstone.
            let mut cleanup = start_cleanup_from_directory(
                cleanup_root.tombstones.as_ref(),
                CleanupPolicy::TombstoneRoot,
                None,
            )
            .unwrap();
            let mut removed = 0;
            loop {
                let batch = cleanup.run_batch(100).unwrap();
                removed += batch.removed;
                if batch.complete {
                    break;
                }
            }
            assert_eq!(removed, 0);
        });

        let error = match staged.commit(false) {
            Ok(_) => panic!("empty-only delete unexpectedly accepted late content"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::DirectoryNotEmpty);
        assert_eq!(
            std::fs::read(directory.path().join("empty/late.txt")).unwrap(),
            b"must survive"
        );
        assert!(root.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn ambiguous_empty_directory_probe_preserves_intent_and_blocks_cleanup() {
        use std::os::fd::AsRawFd;

        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::create_dir(directory.path().join("empty")).unwrap();
        let external_writer = File::open(directory.path().join("empty")).unwrap();
        let mut staged = root.stage_delete("empty").unwrap();
        staged.run_after_promotion(move || {
            std::fs::write(
                format!("/proc/self/fd/{}/late.txt", external_writer.as_raw_fd()),
                b"must survive ambiguous probe",
            )
            .unwrap();
        });
        root.fail_next_delete_identity_probe(io::ErrorKind::WouldBlock);

        let error = staged
            .commit(false)
            .err()
            .expect("ambiguous identity probe must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        let pending = root.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        let tombstone_name = match &pending[0].operation {
            DurableFileOperation::Delete {
                tombstone_name,
                allow_recursive,
                ..
            } => {
                assert!(!allow_recursive);
                tombstone_name.clone()
            }
            DurableFileOperation::Rename { .. } => panic!("expected delete intent"),
        };
        let tombstone_path = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            .join(&tombstone_name);
        assert_eq!(
            std::fs::read(tombstone_path.join("late.txt")).unwrap(),
            b"must survive ambiguous probe"
        );

        // Simulate a fresh process without the in-memory guard. Both targeted
        // and generic cleanup still fail closed because the durable intent is
        // consulted live.
        unregister_upload_fragment(&tombstone_name);
        assert_eq!(
            root.start_deletion_cleanup(&tombstone_name)
                .err()
                .expect("durable intent must block targeted cleanup")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        let mut removed = 0;
        loop {
            let batch = cleanup.run_batch(100).unwrap();
            removed += batch.removed;
            if batch.complete {
                break;
            }
        }
        assert_eq!(removed, 0);
        assert!(tombstone_path.join("late.txt").is_file());

        root.fail_next_delete_identity_probe(io::ErrorKind::TimedOut);
        let recovery_error = root.recover_file_operation(&pending[0]).unwrap_err();
        assert_eq!(recovery_error.kind(), io::ErrorKind::TimedOut);
        assert!(tombstone_path.join("late.txt").is_file());
        assert_eq!(root.pending_file_operations().unwrap().len(), 1);
    }

    #[test]
    fn phase_less_legacy_journals_deserialize_as_moved() {
        let rename: DurableFileOperation = serde_json::from_value(serde_json::json!({
            "operation": "rename",
            "original_path": "before.txt",
            "new_path": "after.txt",
            "kind": "file",
            "device": 1,
            "inode": 2
        }))
        .unwrap();
        assert!(matches!(
            rename,
            DurableFileOperation::Rename {
                phase: DurableRenamePhase::Moved,
                ..
            }
        ));

        let delete: DurableFileOperation = serde_json::from_value(serde_json::json!({
            "operation": "delete",
            "original_path": "old.txt",
            "kind": "file",
            "device": 1,
            "inode": 2,
            "pending_name": deletion_pending_name(),
            "tombstone_name": deletion_tombstone_name(),
            "allow_recursive": false
        }))
        .unwrap();
        assert!(matches!(
            delete,
            DurableFileOperation::Delete {
                phase: DurableDeletePhase::Moved,
                ..
            }
        ));
    }

    #[test]
    fn rename_rollback_journal_cancels_after_namespace_was_restored() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("before.txt"), b"content").unwrap();

        let mut staged = root.stage_rename("before.txt", "after.txt").unwrap();
        replace_file_operation(
            &staged.operation_staging,
            &staged.operation_name,
            &DurableFileOperation::Rename {
                original_path: staged.original_path.clone(),
                new_path: staged.new_path.clone(),
                kind: staged.kind.into(),
                device: staged.source_identity.0,
                inode: staged.source_identity.1,
                phase: DurableRenamePhase::Rollback,
            },
        )
        .unwrap();
        linux::rename_noreplace(&staged.parent, &staged.new_name, &staged.original_name).unwrap();
        staged.parent.sync_all().unwrap();
        staged.committed = true;
        drop(staged);

        let pending = root.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            root.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Cancelled
        );
        assert_eq!(
            std::fs::read(directory.path().join("before.txt")).unwrap(),
            b"content"
        );
        assert!(!directory.path().join("after.txt").exists());
        assert!(root.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn delete_intent_recovery_restores_the_pending_source_without_db_commit() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("restore.txt"), b"content").unwrap();

        let mut staged = root.stage_delete("restore.txt").unwrap();
        let operation = DurableFileOperation::Delete {
            original_path: staged.original_path.clone(),
            kind: staged.status.kind.into(),
            device: staged.source_identity.0,
            inode: staged.source_identity.1,
            pending_name: staged.tombstone_name.clone(),
            tombstone_name: deletion_tombstone_name(),
            allow_recursive: false,
            phase: DurableDeletePhase::Intent,
        };
        write_file_operation(root.tombstones.as_ref(), &operation).unwrap();
        staged.committed = true;
        staged.release_active();
        drop(staged);

        let pending = root.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            root.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Cancelled
        );
        assert_eq!(
            std::fs::read(directory.path().join("restore.txt")).unwrap(),
            b"content"
        );
        assert!(root.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn delete_rollback_journal_cancels_after_visible_restoration() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::create_dir(directory.path().join("restore-dir")).unwrap();

        let mut staged = root.stage_delete("restore-dir").unwrap();
        let (committed_name, operation_name) = staged.promote_for_cleanup(false).unwrap();
        assert_eq!(committed_name, staged.tombstone_name);
        replace_delete_operation_phase(
            &staged.staging,
            &operation_name,
            DurableDeletePhase::Rollback,
        )
        .unwrap();
        linux::rename_noreplace_between(
            &staged.staging,
            &staged.tombstone_name,
            &staged.parent,
            &staged.original_name,
        )
        .unwrap();
        staged.parent.sync_all().unwrap();
        staged.staging.sync_all().unwrap();
        staged.committed = true;
        staged.release_active();
        drop(staged);

        let pending = root.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            root.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Cancelled
        );
        assert!(directory.path().join("restore-dir").is_dir());
        assert!(root.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn interrupted_rename_intent_is_idempotently_recovered() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("before.txt"), b"content").unwrap();

        let mut staged = root.stage_rename("before.txt", "after.txt").unwrap();
        staged.begin_database_commit();
        drop(staged);
        drop(root);

        let reopened = SecureRoot::open(directory.path()).unwrap();
        let pending = reopened.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            reopened.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Rename {
                original_path: "before.txt".into(),
                new_path: "after.txt".into(),
                is_directory: false,
            }
        );
        reopened.complete_file_operation(&pending[0]).unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("after.txt")).unwrap(),
            b"content"
        );
        assert!(reopened.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn moved_rename_recovery_preserves_old_path_replacement_even_with_matching_identity() {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("before.txt"), b"replacement").unwrap();
        let replacement = std::fs::metadata(directory.path().join("before.txt")).unwrap();
        let operation = DurableFileOperation::Rename {
            original_path: "before.txt".into(),
            new_path: "after.txt".into(),
            kind: DurableEntryKind::File,
            // Deliberately model dev/inode reuse after the completed target at
            // the new path was removed.
            device: replacement.dev(),
            inode: replacement.ino(),
            phase: DurableRenamePhase::Moved,
        };
        write_file_operation(root.tombstones.as_ref(), &operation).unwrap();
        let pending = root.pending_file_operations().unwrap();

        assert_eq!(
            root.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Rename {
                original_path: "before.txt".into(),
                new_path: "after.txt".into(),
                is_directory: false,
            }
        );
        assert_eq!(
            std::fs::read(directory.path().join("before.txt")).unwrap(),
            b"replacement"
        );
        assert!(!directory.path().join("after.txt").exists());
        root.complete_file_operation(&pending[0]).unwrap();
    }

    #[test]
    fn intent_rename_recovery_cancels_in_place_instead_of_replaying_old_name() {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("before.txt"), b"replacement").unwrap();
        let replacement = std::fs::metadata(directory.path().join("before.txt")).unwrap();
        let operation = DurableFileOperation::Rename {
            original_path: "before.txt".into(),
            new_path: "after.txt".into(),
            kind: DurableEntryKind::File,
            // This deliberately also matches the recorded identity, modeling
            // inode reuse in the crash window before the moved marker landed.
            device: replacement.dev(),
            inode: replacement.ino(),
            phase: DurableRenamePhase::Intent,
        };
        write_file_operation(root.tombstones.as_ref(), &operation).unwrap();
        let pending = root.pending_file_operations().unwrap();

        assert_eq!(
            root.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Cancelled
        );
        assert_eq!(
            std::fs::read(directory.path().join("before.txt")).unwrap(),
            b"replacement"
        );
        assert!(!directory.path().join("after.txt").exists());
        assert!(root.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn rename_verifies_the_moved_inode_after_source_name_swap() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let source = directory.path().join("source.txt");
        let externally_moved = directory.path().join("externally-moved.txt");
        std::fs::write(&source, b"authorized").unwrap();
        let hook_source = source.clone();
        let hook_external = externally_moved.clone();
        let hook_replacement = source;
        root.before_next_rename(move || {
            std::fs::rename(hook_source, hook_external).unwrap();
            std::fs::write(hook_replacement, b"replacement").unwrap();
        });

        let error = root
            .stage_rename("source.txt", "renamed.txt")
            .err()
            .expect("source-name replacement must fail identity verification");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(externally_moved).unwrap(), b"authorized");
        assert_eq!(
            std::fs::read(directory.path().join("renamed.txt")).unwrap(),
            b"replacement"
        );
        assert_eq!(root.pending_file_operations().unwrap().len(), 1);
    }

    #[test]
    fn interrupted_committed_delete_retains_recovery_metadata_until_reconciled() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::create_dir(directory.path().join("tree")).unwrap();
        std::fs::write(directory.path().join("tree/child.txt"), b"content").unwrap();

        let committed = root.stage_delete("tree").unwrap().commit(true).unwrap();
        let tombstone = committed.outcome().tombstone_path.as_ref().unwrap().clone();
        drop(committed);
        drop(root);

        let reopened = SecureRoot::open(directory.path()).unwrap();
        let pending = reopened.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            reopened.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Delete {
                original_path: "tree".into(),
                is_directory: true,
                tombstone_path: Some(tombstone.clone()),
            }
        );
        reopened.complete_file_operation(&pending[0]).unwrap();
        let mut cleanup = reopened.start_deletion_cleanup(&tombstone).unwrap();
        while !cleanup.run_batch(1).unwrap().complete {}
        assert!(!directory.path().join("tree").exists());
        assert!(reopened.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn delete_recovery_never_reclaims_visible_original_when_private_names_are_missing() {
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("reused.txt"), b"replacement").unwrap();
        let replacement = std::fs::metadata(directory.path().join("reused.txt")).unwrap();
        let operation = DurableFileOperation::Delete {
            original_path: "reused.txt".into(),
            kind: DurableEntryKind::File,
            // Deliberately record the replacement identity to model dev/inode
            // reuse after the original target was unlinked.
            device: replacement.dev(),
            inode: replacement.ino(),
            pending_name: deletion_pending_name(),
            tombstone_name: deletion_tombstone_name(),
            allow_recursive: false,
            phase: DurableDeletePhase::Moved,
        };
        write_file_operation(root.tombstones.as_ref(), &operation).unwrap();
        let pending = root.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);

        assert_eq!(
            root.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Delete {
                original_path: "reused.txt".into(),
                is_directory: false,
                tombstone_path: None,
            }
        );
        assert_eq!(
            std::fs::read(directory.path().join("reused.txt")).unwrap(),
            b"replacement"
        );
        root.complete_file_operation(&pending[0]).unwrap();
    }

    #[test]
    fn rename_rejects_symlink_sources_without_moving_them() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("target.txt"), b"target").unwrap();
        symlink("target.txt", directory.path().join("link.txt")).unwrap();

        let error = match root.stage_rename("link.txt", "moved.txt") {
            Ok(_) => panic!("symlink rename unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(directory.path().join("link.txt").is_symlink());
        assert!(!directory.path().join("moved.txt").exists());
    }

    #[test]
    fn cleanup_removes_only_flat_private_upload_fragments() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let staging = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(UPLOAD_STAGING_DIRECTORY_NAME);
        let nested = staging.join("nested");
        std::fs::create_dir(&nested).unwrap();
        let first = upload_fragment_name();
        let second = upload_fragment_name();
        std::fs::write(staging.join(&first), b"partial").unwrap();
        std::fs::write(nested.join(&second), b"partial").unwrap();
        let public_fragment = upload_fragment_name();
        std::fs::write(directory.path().join(&public_fragment), b"client-owned").unwrap();
        std::fs::write(staging.join("keep.part"), b"keep").unwrap();
        let matching_directory = staging.join(upload_fragment_name());
        std::fs::create_dir(&matching_directory).unwrap();

        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        let batch = cleanup.run_batch(100).unwrap();
        assert!(batch.complete);
        assert_eq!(batch.removed, 1);
        assert!(!staging.join(first).exists());
        assert_eq!(std::fs::read(nested.join(second)).unwrap(), b"partial");
        assert_eq!(std::fs::read(staging.join("keep.part")).unwrap(), b"keep");
        assert!(matching_directory.is_dir());
        assert_eq!(
            std::fs::read(directory.path().join(public_fragment)).unwrap(),
            b"client-owned"
        );
    }

    #[test]
    fn cleanup_stops_at_the_configured_scan_bound() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let staging = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(UPLOAD_STAGING_DIRECTORY_NAME);
        std::fs::write(staging.join(upload_fragment_name()), b"one").unwrap();
        std::fs::write(staging.join(upload_fragment_name()), b"two").unwrap();
        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        let batch = cleanup.run_batch(1).unwrap();
        assert_eq!(batch.scanned, 1);
        assert!(!batch.complete);
    }

    #[test]
    fn directory_scan_counts_filtered_raw_items() {
        let directory = tempfile::tempdir().unwrap();
        let fragment = upload_fragment_name();
        std::fs::write(directory.path().join(&fragment), b"partial").unwrap();
        std::fs::write(directory.path().join("visible.txt"), b"visible").unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();

        let mut scan = root.scan_directory("").unwrap();
        let mut scanned = 0usize;
        let mut names = Vec::new();
        loop {
            let batch = scan.run_batch(1).unwrap();
            assert!(batch.scanned <= 1);
            scanned += batch.scanned;
            names.extend(batch.entries.into_iter().map(|entry| entry.name));
            if batch.complete {
                break;
            }
        }
        assert_eq!(scanned, 3);
        assert_eq!(names, vec!["visible.txt"]);
    }

    #[test]
    fn cleanup_continues_across_strictly_bounded_batches() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let staging = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(UPLOAD_STAGING_DIRECTORY_NAME);
        let mut fragments = Vec::new();
        for index in 0usize..16 {
            let fragment = upload_fragment_name();
            std::fs::write(staging.join(&fragment), b"partial").unwrap();
            std::fs::write(staging.join(format!("keep-{index}.txt")), b"keep").unwrap();
            fragments.push(staging.join(fragment));
        }
        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        let mut removed = 0usize;
        for _ in 0..256 {
            let batch = cleanup.run_batch(1).unwrap();
            assert!(batch.scanned <= 1);
            removed += batch.removed;
            if batch.complete {
                break;
            }
        }

        assert_eq!(removed, fragments.len());
        assert!(fragments.iter().all(|path| !path.exists()));
        assert!(staging.join("keep-0.txt").is_file());
        assert!(staging.join("keep-1.txt").is_file());
    }

    #[test]
    fn recursive_cleanup_depth_limit_is_retryable_and_stays_inside_the_tombstone() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("must-survive.txt");
        std::fs::write(&outside_file, b"outside").unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let tombstone_name = deletion_tombstone_name();
        let tombstone = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            .join(&tombstone_name);
        std::fs::create_dir(&tombstone).unwrap();
        let mut deepest = tombstone.clone();
        for index in 0..(MAX_CLEANUP_DIRECTORY_STACK * 3) {
            deepest = deepest.join(format!("d{index}"));
            std::fs::create_dir(&deepest).unwrap();
        }
        std::fs::write(deepest.join("payload.txt"), b"private").unwrap();
        symlink(outside.path(), deepest.join("outside-link")).unwrap();

        let mut limit_errors = 0usize;
        let mut complete = false;
        for _ in 0..16 {
            let mut cleanup = root.start_deletion_cleanup(&tombstone_name).unwrap();
            loop {
                match cleanup.run_batch(8) {
                    Ok(batch) if batch.complete => {
                        complete = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        assert_eq!(
                            error.kind(),
                            io::ErrorKind::WouldBlock,
                            "unexpected cleanup error: {error:?}, raw={:?}",
                            error.raw_os_error()
                        );
                        assert!(cleanup.directories.len() <= MAX_CLEANUP_DIRECTORY_STACK);
                        limit_errors += 1;
                        break;
                    }
                }
            }
            assert_eq!(std::fs::read(&outside_file).unwrap(), b"outside");
            if complete {
                break;
            }
        }

        assert!(complete, "segmented cleanup retries did not finish");
        assert!(limit_errors > 0, "test did not exercise the depth limit");
        assert!(!tombstone.exists());
        assert_eq!(std::fs::read(outside_file).unwrap(), b"outside");
    }

    #[test]
    fn cleanup_segmentation_rejects_a_replaced_source_name() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let tombstone_name = deletion_tombstone_name();
        let tombstone = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            .join(&tombstone_name);
        let parent = tombstone.join("parent");
        let current = parent.join("current");
        std::fs::create_dir(&tombstone).unwrap();
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&current).unwrap();
        std::fs::write(current.join("original.txt"), b"original").unwrap();

        let mut cleanup = root.start_deletion_cleanup(&tombstone_name).unwrap();
        assert!(!cleanup.run_batch(1).unwrap().complete);
        assert!(!cleanup.run_batch(1).unwrap().complete);
        assert_eq!(cleanup.directories.len(), 3);

        let moved = parent.join("moved-current");
        std::fs::rename(&current, &moved).unwrap();
        std::fs::create_dir(&current).unwrap();
        std::fs::write(current.join("replacement.txt"), b"replacement").unwrap();

        let error = rebase_cleanup_directory(cleanup.directories.last().unwrap()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(
            std::fs::read(moved.join("original.txt")).unwrap(),
            b"original"
        );
        assert_eq!(
            std::fs::read(current.join("replacement.txt")).unwrap(),
            b"replacement"
        );
        assert!(std::fs::read_dir(&tombstone).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(CLEANUP_SEGMENT_PREFIX)
        }));
    }

    #[test]
    fn recursive_cleanup_visited_limit_makes_bounded_progress_across_retries() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let public_file = directory.path().join("must-survive.txt");
        std::fs::write(&public_file, b"public").unwrap();
        let tombstone_name = deletion_tombstone_name();
        let tombstone = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            .join(&tombstone_name);
        std::fs::create_dir(&tombstone).unwrap();
        for index in 0..6 {
            let child = tombstone.join(format!("child-{index}"));
            std::fs::create_dir(&child).unwrap();
            std::fs::write(child.join("payload.txt"), b"private").unwrap();
        }

        let mut limit_errors = 0usize;
        let mut complete = false;
        for _ in 0..16 {
            let mut cleanup = root.start_deletion_cleanup(&tombstone_name).unwrap();
            cleanup.max_visited_directories = 2;
            loop {
                match cleanup.run_batch(2) {
                    Ok(batch) if batch.complete => {
                        complete = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                        assert!(cleanup.visited.len() <= cleanup.max_visited_directories);
                        limit_errors += 1;
                        break;
                    }
                }
            }
            if complete {
                break;
            }
        }

        assert!(complete, "bounded cleanup retries did not finish");
        assert!(limit_errors > 0, "test did not exercise the visited limit");
        assert!(!tombstone.exists());
        assert_eq!(std::fs::read(public_file).unwrap(), b"public");
    }

    #[test]
    fn cleanup_respects_a_fragment_reserved_before_creation() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let fragment = upload_fragment_name();
        let fragment_path = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(UPLOAD_STAGING_DIRECTORY_NAME)
            .join(&fragment);

        // PendingUpload reserves the random name before the SMB create, so
        // cleanup cannot observe an unregistered fragment at any point.
        let active_key = fragment;
        assert!(active_upload_fragment_guard().insert(active_key.clone()));
        std::fs::write(&fragment_path, b"active").unwrap();
        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        let mut removed = 0usize;
        loop {
            let batch = cleanup.run_batch(1).unwrap();
            removed += batch.removed;
            if batch.complete {
                break;
            }
        }
        assert_eq!(removed, 0);
        assert_eq!(std::fs::read(&fragment_path).unwrap(), b"active");
        unregister_upload_fragment(&active_key);
    }

    #[test]
    fn cleanup_skips_a_live_pending_upload() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let mut pending = root.begin_upload("").unwrap();
        pending.take_file().unwrap().write_all(b"active").unwrap();
        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        loop {
            let batch = cleanup.run_batch(1).unwrap();
            assert_eq!(batch.removed, 0);
            if batch.complete {
                break;
            }
        }
        pending.publish("published.txt").unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("published.txt")).unwrap(),
            b"active"
        );
    }

    #[test]
    fn upload_staging_is_reserved_hidden_and_separate_from_destination() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let staging = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(UPLOAD_STAGING_DIRECTORY_NAME);
        let mut pending = root.begin_upload("").unwrap();

        assert!(root.bind_directory(INTERNAL_DIRECTORY_NAME).is_err());
        assert!(root.list("", 0, 100).unwrap().is_empty());
        assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 1);
        let mut file = pending.take_file().unwrap();
        file.write_all(b"complete").unwrap();
        file.sync_all().unwrap();
        drop(file);
        pending.publish("published.txt").unwrap();

        assert_eq!(std::fs::read_dir(staging).unwrap().count(), 0);
        assert_eq!(
            std::fs::read(directory.path().join("published.txt")).unwrap(),
            b"complete"
        );
    }

    #[test]
    fn cleanup_skips_an_active_deletion_tombstone() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("keep.txt"), b"keep").unwrap();
        let staged = root.stage_delete("keep.txt").unwrap();
        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        let mut removed = 0;
        loop {
            let batch = cleanup.run_batch(1).unwrap();
            removed += batch.removed;
            if batch.complete {
                break;
            }
        }
        assert_eq!(removed, 0);
        drop(staged);
        assert_eq!(
            std::fs::read(directory.path().join("keep.txt")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn delete_staging_reconciles_executed_rename_reported_as_exists() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("response-loss.txt"), b"original").unwrap();
        root.fail_next_delete_staging_rename_after_success(io::ErrorKind::AlreadyExists);

        let staged = root.stage_delete("response-loss.txt").unwrap();
        assert!(!directory.path().join("response-loss.txt").exists());
        let recovery_path = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            .join(&staged.tombstone_name);
        assert_eq!(std::fs::read(&recovery_path).unwrap(), b"original");
        assert!(recovery_path
            .with_file_name(deletion_manifest_name(&staged.tombstone_name))
            .is_file());

        drop(staged);
        assert_eq!(
            std::fs::read(directory.path().join("response-loss.txt")).unwrap(),
            b"original"
        );
        assert_eq!(
            std::fs::read_dir(
                directory
                    .path()
                    .join(INTERNAL_DIRECTORY_NAME)
                    .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            )
            .unwrap()
            .count(),
            0
        );
    }

    #[test]
    fn deletion_promotion_reconciles_response_loss_before_exists_handling() {
        for error_kind in [io::ErrorKind::AlreadyExists, io::ErrorKind::Other] {
            let directory = tempfile::tempdir().unwrap();
            let root = SecureRoot::open(directory.path()).unwrap();
            std::fs::write(directory.path().join("commit.txt"), b"content").unwrap();
            let staged = root.stage_delete("commit.txt").unwrap();
            root.fail_next_delete_promotion_rename_after_success(error_kind);

            let outcome = staged.commit(false).unwrap().complete().unwrap();
            assert_eq!(
                outcome,
                DeleteCommitOutcome {
                    cleanup_pending: false,
                    tombstone_path: None,
                }
            );
            assert!(!directory.path().join("commit.txt").exists());
            assert_eq!(
                std::fs::read_dir(
                    directory
                        .path()
                        .join(INTERNAL_DIRECTORY_NAME)
                        .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
                )
                .unwrap()
                .count(),
                0
            );
        }
    }

    #[test]
    fn rollback_conflict_preserves_recovery_entry_and_new_external_file() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("report.txt"), b"original").unwrap();
        let staged = root.stage_delete("report.txt").unwrap();
        let recovery_name = staged.tombstone_name.clone();

        // Simulate a co-writer reusing the visible name before rollback.
        std::fs::write(directory.path().join("report.txt"), b"external").unwrap();
        drop(staged);

        assert_eq!(
            std::fs::read(directory.path().join("report.txt")).unwrap(),
            b"external"
        );
        let recovery_path = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            .join(&recovery_name);
        let manifest_path = recovery_path.with_file_name(deletion_manifest_name(&recovery_name));
        assert_eq!(std::fs::read(&recovery_path).unwrap(), b"original");
        assert!(manifest_path.is_file());
        let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
        let batch = cleanup.run_batch(100).unwrap();
        assert!(batch.complete);
        assert_eq!(batch.removed, 0);
        assert_eq!(std::fs::read(recovery_path).unwrap(), b"original");
        drop(root);
        let error = SecureRoot::open(directory.path())
            .err()
            .expect("startup must refuse an unresolved unjournaled rollback conflict");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(directory.path().join("report.txt")).unwrap(),
            b"external"
        );
        assert!(manifest_path.is_file());
    }

    #[test]
    fn restart_restores_uncommitted_pending_delete_from_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("restore.txt"), b"original").unwrap();
        let staged = root.stage_delete("restore.txt").unwrap();
        let active_key = staged.active_key.clone().unwrap();

        // Simulate process loss: Drop cannot run and the in-memory registry is
        // empty in the next process, while pending data + durable manifest remain.
        std::mem::forget(staged);
        unregister_upload_fragment(&active_key);
        drop(root);

        let reopened = SecureRoot::open(directory.path()).unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("restore.txt")).unwrap(),
            b"original"
        );
        let tombstones = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME);
        assert_eq!(std::fs::read_dir(tombstones).unwrap().count(), 0);
        drop(reopened);
    }

    #[test]
    fn restart_restores_every_unjournaled_delete_and_preserves_journaled_work() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let mut staged_deletes = Vec::new();
        for index in 0..32 {
            let path = format!("restore-{index}.txt");
            std::fs::write(directory.path().join(&path), path.as_bytes()).unwrap();
            staged_deletes.push((path.clone(), root.stage_delete(&path).unwrap()));
        }
        std::fs::write(directory.path().join("forward.txt"), b"forward").unwrap();
        let forward = root.stage_delete("forward.txt").unwrap();
        let forward_operation = DurableFileOperation::Delete {
            original_path: forward.original_path.clone(),
            kind: forward.status.kind.into(),
            device: forward.source_identity.0,
            inode: forward.source_identity.1,
            pending_name: forward.tombstone_name.clone(),
            tombstone_name: deletion_tombstone_name(),
            allow_recursive: false,
            phase: DurableDeletePhase::Moved,
        };
        write_file_operation(root.tombstones.as_ref(), &forward_operation).unwrap();

        for (_, staged) in staged_deletes.iter() {
            unregister_upload_fragment(staged.active_key.as_ref().unwrap());
        }
        unregister_upload_fragment(forward.active_key.as_ref().unwrap());
        for (_, staged) in staged_deletes {
            std::mem::forget(staged);
        }
        std::mem::forget(forward);
        drop(root);

        let reopened = SecureRoot::open(directory.path()).unwrap();
        for index in 0..32 {
            let path = format!("restore-{index}.txt");
            assert_eq!(
                std::fs::read(directory.path().join(&path)).unwrap(),
                path.as_bytes()
            );
        }
        assert!(!directory.path().join("forward.txt").exists());
        let pending = reopened.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            reopened.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Delete {
                original_path: "forward.txt".into(),
                is_directory: false,
                tombstone_path: None,
            }
        );
        reopened.complete_file_operation(&pending[0]).unwrap();
        assert!(reopened.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn restart_refuses_unjournaled_pending_delete_when_original_was_reused() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("shared.txt"), b"original").unwrap();
        let staged = root.stage_delete("shared.txt").unwrap();
        let pending_name = staged.tombstone_name.clone();
        let active_key = staged.active_key.clone().unwrap();
        std::fs::write(directory.path().join("shared.txt"), b"replacement").unwrap();

        std::mem::forget(staged);
        unregister_upload_fragment(&active_key);
        drop(root);

        let error = SecureRoot::open(directory.path())
            .err()
            .expect("startup must fail closed while an unjournaled delete cannot roll back");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(directory.path().join("shared.txt")).unwrap(),
            b"replacement"
        );
        let recovery_path = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME)
            .join(pending_name);
        assert_eq!(std::fs::read(recovery_path).unwrap(), b"original");
    }

    #[test]
    fn restart_leaves_journaled_pending_delete_for_forward_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("forward.txt"), b"content").unwrap();
        let staged = root.stage_delete("forward.txt").unwrap();
        let active_key = staged.active_key.clone().unwrap();
        let committed_name = deletion_tombstone_name();
        let operation = DurableFileOperation::Delete {
            original_path: staged.original_path.clone(),
            kind: staged.status.kind.into(),
            device: staged.source_identity.0,
            inode: staged.source_identity.1,
            pending_name: staged.tombstone_name.clone(),
            tombstone_name: committed_name,
            allow_recursive: false,
            phase: DurableDeletePhase::Moved,
        };
        write_file_operation(root.tombstones.as_ref(), &operation).unwrap();

        std::mem::forget(staged);
        unregister_upload_fragment(&active_key);
        drop(root);

        let reopened = SecureRoot::open(directory.path()).unwrap();
        assert!(!directory.path().join("forward.txt").exists());
        let pending = reopened.pending_file_operations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            reopened.recover_file_operation(&pending[0]).unwrap(),
            FileOperationRecovery::Delete {
                original_path: "forward.txt".into(),
                is_directory: false,
                tombstone_path: None,
            }
        );
        reopened.complete_file_operation(&pending[0]).unwrap();
        assert!(reopened.pending_file_operations().unwrap().is_empty());
    }

    #[test]
    fn startup_removes_only_strict_incomplete_operation_journal_names() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let tombstones = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME);
        let temporary_names = (0..32)
            .map(|_| format!("{}.pending", file_operation_name()))
            .collect::<Vec<_>>();
        let unknown_name = format!("{}.pending.backup", file_operation_name());
        let orphan_manifests = (0..32)
            .map(|_| deletion_manifest_name(&deletion_pending_name()))
            .collect::<Vec<_>>();
        let unknown_manifest = format!("not-a-delete{DELETION_MANIFEST_SUFFIX}");
        for temporary_name in &temporary_names {
            std::fs::write(tombstones.join(temporary_name), b"partial").unwrap();
        }
        std::fs::write(tombstones.join(&unknown_name), b"preserve").unwrap();
        for orphan_manifest in &orphan_manifests {
            std::fs::write(tombstones.join(orphan_manifest), b"orphan").unwrap();
        }
        std::fs::write(tombstones.join(&unknown_manifest), b"preserve manifest").unwrap();
        drop(root);

        let reopened = SecureRoot::open(directory.path()).unwrap();
        assert!(temporary_names
            .iter()
            .all(|temporary_name| !tombstones.join(temporary_name).exists()));
        assert!(orphan_manifests
            .iter()
            .all(|orphan_manifest| !tombstones.join(orphan_manifest).exists()));
        assert_eq!(
            std::fs::read(tombstones.join(unknown_name)).unwrap(),
            b"preserve"
        );
        assert_eq!(
            std::fs::read(tombstones.join(unknown_manifest)).unwrap(),
            b"preserve manifest"
        );
        drop(reopened);
    }

    #[test]
    fn committed_delete_removes_pending_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("delete.txt"), b"content").unwrap();
        let staged = root.stage_delete("delete.txt").unwrap();
        assert!(staged
            .commit(false)
            .unwrap()
            .complete()
            .unwrap()
            .tombstone_path
            .is_none());
        let tombstones = directory
            .path()
            .join(INTERNAL_DIRECTORY_NAME)
            .join(TOMBSTONE_STAGING_DIRECTORY_NAME);
        assert_eq!(std::fs::read_dir(tombstones).unwrap().count(), 0);
    }

    #[test]
    fn preprovisioned_sibling_staging_cannot_be_reached_through_share_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let mount = tempfile::tempdir().unwrap();
        let shared = mount.path().join("shared");
        let internal = mount.path().join(INTERNAL_DIRECTORY_NAME);
        std::fs::create_dir(&shared).unwrap();
        std::fs::create_dir(&internal).unwrap();
        std::fs::create_dir(internal.join(UPLOAD_STAGING_DIRECTORY_NAME)).unwrap();
        std::fs::create_dir(internal.join(TOMBSTONE_STAGING_DIRECTORY_NAME)).unwrap();
        for path in [
            internal.as_path(),
            &internal.join(UPLOAD_STAGING_DIRECTORY_NAME),
            &internal.join(TOMBSTONE_STAGING_DIRECTORY_NAME),
        ] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let root = SecureRoot::open_configured(&shared, Some(&internal), true, true).unwrap();
        symlink("../.vaultlink-internal", shared.join("leak")).unwrap();

        assert!(root.bind_directory("leak/uploads").is_err());
    }

    #[test]
    fn nested_reserved_internal_storage_is_filtered_and_unreachable() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let shared = tempfile::tempdir().unwrap();
        let internal = shared.path().join(INTERNAL_DIRECTORY_NAME);
        std::fs::create_dir(&internal).unwrap();
        std::fs::create_dir(internal.join(UPLOAD_STAGING_DIRECTORY_NAME)).unwrap();
        std::fs::create_dir(internal.join(TOMBSTONE_STAGING_DIRECTORY_NAME)).unwrap();
        for path in [
            internal.as_path(),
            &internal.join(UPLOAD_STAGING_DIRECTORY_NAME),
            &internal.join(TOMBSTONE_STAGING_DIRECTORY_NAME),
        ] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(shared.path().join("document.txt"), b"visible").unwrap();
        symlink(
            INTERNAL_DIRECTORY_NAME,
            shared.path().join("internal-alias"),
        )
        .unwrap();

        let root = SecureRoot::open_configured(shared.path(), Some(&internal), true, true).unwrap();
        let entries = root.list("", 0, 100).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "document.txt");
        assert!(root.metadata(INTERNAL_DIRECTORY_NAME).is_err());
        assert!(root.bind_directory("internal-alias/uploads").is_err());
    }

    #[test]
    fn insecure_internal_directory_permissions_fail_closed() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let internal = directory.path().join(INTERNAL_DIRECTORY_NAME);
        std::fs::create_dir(&internal).unwrap();
        std::fs::set_permissions(&internal, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = match SecureRoot::open(directory.path()) {
            Ok(_) => panic!("insecure internal directory was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn special_files_are_hidden_and_never_block_regular_file_open() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        extern "C" {
            fn mkfifo(path: *const std::os::raw::c_char, mode: u32) -> i32;
        }

        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("pipe");
        let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo_path` is a valid, NUL-terminated path for this call.
        assert_eq!(unsafe { mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        let root = SecureRoot::open(directory.path()).unwrap();
        assert!(root.list("", 0, 100).unwrap().is_empty());
        assert_eq!(
            root.open_file("pipe").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn existing_linux_filenames_are_not_reduced_to_windows_upload_policy() {
        let directory = tempfile::tempdir().unwrap();
        for name in ["report:2026.txt", "CON.txt", "frage?.txt", "trailing."] {
            std::fs::write(directory.path().join(name), name).unwrap();
        }
        let root = SecureRoot::open(directory.path()).unwrap();
        let names = root
            .list("", 0, 100)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect::<std::collections::HashSet<_>>();
        for name in ["report:2026.txt", "CON.txt", "frage?.txt", "trailing."] {
            assert!(names.contains(name), "valid Linux file was hidden: {name}");
        }
    }

    #[test]
    fn upload_publish_is_noclobber_and_cleans_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("existing.txt"), b"original").unwrap();

        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"replacement").unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert_eq!(
            upload.publish("existing.txt").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        drop(upload);
        assert_eq!(
            std::fs::read(directory.path().join("existing.txt")).unwrap(),
            b"original"
        );

        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"complete").unwrap();
        file.sync_all().unwrap();
        drop(file);
        upload.publish("complete.txt").unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("complete.txt")).unwrap(),
            b"complete"
        );
    }

    #[test]
    fn pending_upload_revalidates_the_current_destination_inode() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("target")).unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let upload = root.begin_upload("target").unwrap();
        let original = root.bind_directory("target").unwrap();
        assert!(upload.destination_matches(&original).unwrap());

        std::fs::rename(
            directory.path().join("target"),
            directory.path().join("moved-target"),
        )
        .unwrap();
        std::fs::create_dir(directory.path().join("target")).unwrap();

        let replacement = root.bind_directory("target").unwrap();
        let moved = root.bind_directory("moved-target").unwrap();
        assert!(!upload.destination_matches(&replacement).unwrap());
        assert!(upload.destination_matches(&moved).unwrap());
    }

    #[test]
    fn upload_publish_replace_is_atomic_and_cleans_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("existing.txt"), b"original").unwrap();

        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"replacement").unwrap();
        file.sync_all().unwrap();
        drop(file);
        upload.publish_replace("existing.txt").unwrap();
        drop(upload);

        assert_eq!(
            std::fs::read(directory.path().join("existing.txt")).unwrap(),
            b"replacement"
        );
        let remaining_parts = std::fs::read_dir(
            directory
                .path()
                .join(INTERNAL_DIRECTORY_NAME)
                .join(UPLOAD_STAGING_DIRECTORY_NAME),
        )
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".part"))
        .count();
        assert_eq!(remaining_parts, 0);
    }

    #[test]
    fn external_writer_storage_disables_replace_at_the_filesystem_boundary() {
        use std::os::unix::fs::PermissionsExt;

        let mount = tempfile::tempdir().unwrap();
        let shared = mount.path().join("shared");
        let internal = mount.path().join(INTERNAL_DIRECTORY_NAME);
        let uploads = internal.join(UPLOAD_STAGING_DIRECTORY_NAME);
        let tombstones = internal.join(TOMBSTONE_STAGING_DIRECTORY_NAME);
        for path in [&shared, &internal, &uploads, &tombstones] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let root = SecureRoot::open_configured(&shared, Some(&internal), true, true).unwrap();
        std::fs::write(shared.join("existing.txt"), b"original").unwrap();
        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"replacement").unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert_eq!(
            upload.publish_replace("existing.txt").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            std::fs::read(shared.join("existing.txt")).unwrap(),
            b"original"
        );
    }

    #[test]
    fn explicit_external_writer_replace_policy_enables_filesystem_replace() {
        use std::os::unix::fs::PermissionsExt;

        let mount = tempfile::tempdir().unwrap();
        let shared = mount.path().join("shared");
        let internal = mount.path().join(INTERNAL_DIRECTORY_NAME);
        let uploads = internal.join(UPLOAD_STAGING_DIRECTORY_NAME);
        let tombstones = internal.join(TOMBSTONE_STAGING_DIRECTORY_NAME);
        for path in [&shared, &internal, &uploads, &tombstones] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let root =
            SecureRoot::open_configured_inner(&shared, Some(&internal), true, true, true, None)
                .unwrap();
        std::fs::write(shared.join("existing.txt"), b"external").unwrap();
        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"vaultlink").unwrap();
        file.sync_all().unwrap();
        drop(file);

        upload.publish_replace("existing.txt").unwrap();
        assert_eq!(
            std::fs::read(shared.join("existing.txt")).unwrap(),
            b"vaultlink"
        );
    }

    #[test]
    fn abandoned_upload_is_removed() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        {
            let mut upload = root.begin_upload("").unwrap();
            let mut file = upload.take_file().unwrap();
            file.write_all(b"partial").unwrap();
            assert!(root.list("", 0, 100).unwrap().is_empty());
        }
        let names: Vec<_> = std::fs::read_dir(
            directory
                .path()
                .join(INTERNAL_DIRECTORY_NAME)
                .join(UPLOAD_STAGING_DIRECTORY_NAME),
        )
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
        assert!(names.is_empty(), "temporary upload remained: {names:?}");
    }

    #[test]
    fn sync_failure_reports_published_but_uncertain_outcome() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"complete").unwrap();
        file.sync_all().unwrap();
        drop(file);
        upload.fail_next_directory_sync(io::ErrorKind::Other);

        let outcome = upload.publish("complete.txt").unwrap();
        let PublishOutcome::PublishedSyncUncertain(error) = outcome else {
            panic!("injected sync failure was not reported");
        };
        assert_eq!(error.kind(), io::ErrorKind::Other);
        drop(upload);
        assert_eq!(
            std::fs::read(directory.path().join("complete.txt")).unwrap(),
            b"complete"
        );
    }

    #[test]
    fn replace_sync_failure_keeps_the_published_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("existing.txt"), b"old").unwrap();
        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file().unwrap();
        file.write_all(b"new").unwrap();
        file.sync_all().unwrap();
        drop(file);
        upload.fail_next_directory_sync(io::ErrorKind::Other);

        assert!(matches!(
            upload.publish_replace("existing.txt").unwrap(),
            PublishOutcome::PublishedSyncUncertain(_)
        ));
        drop(upload);
        assert_eq!(
            std::fs::read(directory.path().join("existing.txt")).unwrap(),
            b"new"
        );
    }

    #[test]
    fn concurrent_publish_has_exactly_one_winner() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|value| {
                let root = root.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut upload = root.begin_upload("").unwrap();
                    let mut file = upload.take_file().unwrap();
                    file.write_all(value.to_string().as_bytes()).unwrap();
                    file.sync_all().unwrap();
                    drop(file);
                    barrier.wait();
                    upload.publish("same.txt").is_ok()
                })
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
        assert!(directory.path().join("same.txt").is_file());
    }

    #[test]
    fn symlink_escape_is_rejected_for_all_storage_operations() {
        use std::os::unix::fs::symlink;
        let root_directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"secret").unwrap();
        symlink(outside.path(), root_directory.path().join("escape")).unwrap();
        let root = SecureRoot::open(root_directory.path()).unwrap();
        assert!(root.open_file("escape/secret").is_err());
        assert!(root.metadata("escape/secret").is_err());
        assert!(root.list("escape", 0, 100).is_err());
        assert!(root.begin_upload("escape").is_err());
    }

    #[test]
    fn share_scope_allows_internal_symlinks_and_blocks_sibling_share_symlinks() {
        use std::io::Read;
        use std::os::unix::fs::symlink;

        let root_directory = tempfile::tempdir().unwrap();
        let share_a = root_directory.path().join("share-a");
        let share_b = root_directory.path().join("share-b");
        std::fs::create_dir_all(share_a.join("real")).unwrap();
        std::fs::create_dir_all(share_b.join("nested")).unwrap();
        std::fs::create_dir_all(share_b.join("uploads")).unwrap();
        std::fs::write(share_a.join("real/allowed.txt"), b"allowed").unwrap();
        std::fs::write(share_b.join("secret.txt"), b"secret").unwrap();
        symlink("real", share_a.join("inside")).unwrap();
        symlink("../share-b", share_a.join("outside")).unwrap();

        let root = SecureRoot::open(root_directory.path()).unwrap();
        let scope = root.bind_directory("share-a").unwrap();
        let mut allowed = scope.open_file("inside/allowed.txt").unwrap().into_file();
        let mut contents = String::new();
        allowed.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "allowed");

        assert!(scope.open_file("outside/secret.txt").is_err());
        assert!(scope.metadata("outside/secret.txt").is_err());
        assert!(scope.list("outside/nested", 0, 100).is_err());
        assert!(scope.begin_upload("outside/uploads").is_err());

        // Authenticated admin access intentionally remains bounded only by the
        // global storage root, so this in-root path is still available there.
        let mut admin_file = root.open_file("share-a/outside/secret.txt").unwrap();
        contents.clear();
        admin_file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "secret");
    }

    #[test]
    fn bound_directory_descriptor_survives_share_path_retargeting() {
        use std::io::Read;
        use std::os::unix::fs::symlink;

        let root_directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(root_directory.path().join("share-a")).unwrap();
        std::fs::create_dir(root_directory.path().join("share-b")).unwrap();
        std::fs::write(root_directory.path().join("share-a/file.txt"), b"safe").unwrap();
        std::fs::write(root_directory.path().join("share-b/file.txt"), b"secret").unwrap();
        let root = SecureRoot::open(root_directory.path()).unwrap();
        let scope = root.bind_directory("share-a").unwrap();

        std::fs::rename(
            root_directory.path().join("share-a"),
            root_directory.path().join("moved-share-a"),
        )
        .unwrap();
        symlink("share-b", root_directory.path().join("share-a")).unwrap();

        let mut file = scope.open_file("file.txt").unwrap().into_file();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "safe");
        assert!(root.bind_directory("share-a").is_err());
    }
}
