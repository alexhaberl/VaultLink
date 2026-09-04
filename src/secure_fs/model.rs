const DELETION_TOMBSTONE_PREFIX: &str = ".vaultlink-delete-";
const DELETION_TOMBSTONE_SUFFIX: &str = ".tombstone";
const PRIVATE_STORAGE_RANDOM_BYTES: usize = 18;
const PRIVATE_STORAGE_TOKEN_LENGTH: usize = 24;
const CLEANUP_SEGMENT_PREFIX: &str = ".vaultlink-cleanup-segment-";
const DELETION_PENDING_PREFIX: &str = ".vaultlink-delete-pending-";
const DELETION_PENDING_SUFFIX: &str = ".pending";
const DELETION_MANIFEST_SUFFIX: &str = ".manifest";
const FILE_OPERATION_PREFIX: &str = ".vaultlink-operation-";
const FILE_OPERATION_SUFFIX: &str = ".json";
const UPLOAD_FRAGMENT_PREFIX: &str = ".vaultlink-";
const UPLOAD_FRAGMENT_SUFFIX: &str = ".part";
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
        crate::auth::random_token(PRIVATE_STORAGE_RANDOM_BYTES)
    )
}

fn cleanup_segment_name() -> String {
    format!(
        "{CLEANUP_SEGMENT_PREFIX}{}",
        crate::auth::random_token(PRIVATE_STORAGE_RANDOM_BYTES)
    )
}

fn deletion_pending_name() -> String {
    format!(
        "{DELETION_PENDING_PREFIX}{}{DELETION_PENDING_SUFFIX}",
        crate::auth::random_token(PRIVATE_STORAGE_RANDOM_BYTES)
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
    token.len() == PRIVATE_STORAGE_TOKEN_LENGTH
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
        crate::auth::random_token(PRIVATE_STORAGE_RANDOM_BYTES)
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
    token.len() == PRIVATE_STORAGE_TOKEN_LENGTH
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
    token.len() == PRIVATE_STORAGE_TOKEN_LENGTH
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

pub(crate) struct DirectoryTreeOutcome {
    pub(crate) created: Vec<String>,
    pub(crate) sync_error: Option<io::Error>,
    pub(crate) terminal_error: Option<io::Error>,
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
    next_delete_staging_identity_probe_errors: Arc<Mutex<Option<(io::ErrorKind, usize)>>>,
    #[cfg(test)]
    next_delete_post_stage_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_delete_rollback_rename_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_delete_rollback_rename_response_loss: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_delete_rollback_parent_sync_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_delete_promotion_rename_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_delete_identity_probe_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_rename_parent_sync_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_delete_commit_sync_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    before_rename_hook: Arc<Mutex<Option<TestOnceHook>>>,
    #[cfg(test)]
    next_cleanup_start_errors: Arc<Mutex<Option<(io::ErrorKind, usize)>>>,
    #[cfg(test)]
    next_cleanup_batch_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_create_directory_sync_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_create_directory_mkdir_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_create_directory_probe_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_upload_publication_rename_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_upload_publication_identity_probe_errors: Arc<Mutex<Option<(io::ErrorKind, usize)>>>,
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
    #[cfg(test)]
    next_create_directory_mkdir_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_create_directory_probe_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_upload_publication_rename_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_upload_publication_identity_probe_errors: Arc<Mutex<Option<(io::ErrorKind, usize)>>>,
    #[cfg(test)]
    after_directory_tree_create_hook: Arc<Mutex<Option<TestOnceHook>>>,
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
    next_commit_sync_error: Arc<Mutex<Option<io::ErrorKind>>>,
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

pub(crate) enum RenameStageOutcome {
    Ready(StagedRename),
    PublishedUncertain {
        new_path: String,
        kind: EntryKind,
        error: io::Error,
    },
}

pub(crate) enum DeleteCommitStageOutcome {
    Ready(PendingDeleteCommit),
    PublishedUncertain {
        cleanup_pending: bool,
        error: io::Error,
    },
}

pub(crate) enum DeleteStageOutcome {
    Ready(Box<StagedDelete>),
    PublishedUncertain {
        original_path: String,
        kind: EntryKind,
        error: io::Error,
    },
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
