//! Descriptor-relative storage access. Linux production builds use `openat2(2)`
//! so a path cannot escape the configured root between validation and use.

use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::SystemTime,
};

#[cfg(target_os = "linux")]
use std::sync::Arc;

use crate::path_security;

const UPLOAD_FRAGMENT_PREFIX: &str = ".vaultlink-";
const UPLOAD_FRAGMENT_SUFFIX: &str = ".part";
const UPLOAD_FRAGMENT_TOKEN_LENGTH: usize = 24;
const DELETION_TOMBSTONE_PREFIX: &str = ".vaultlink-delete-";
const DELETION_TOMBSTONE_SUFFIX: &str = ".tombstone";
const DELETION_TOMBSTONE_TOKEN_LENGTH: usize = 24;

#[cfg(target_os = "linux")]
type ActiveUploadFragmentKey = (u64, u64);
#[cfg(not(target_os = "linux"))]
type ActiveUploadFragmentKey = PathBuf;

static ACTIVE_UPLOAD_FRAGMENTS: OnceLock<Mutex<HashSet<ActiveUploadFragmentKey>>> = OnceLock::new();

fn active_upload_fragments() -> &'static Mutex<HashSet<ActiveUploadFragmentKey>> {
    ACTIVE_UPLOAD_FRAGMENTS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn active_upload_fragment_guard() -> std::sync::MutexGuard<'static, HashSet<ActiveUploadFragmentKey>>
{
    active_upload_fragments()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn unregister_upload_fragment(key: &ActiveUploadFragmentKey) {
    active_upload_fragment_guard().remove(key);
}

/// Generates the private filename used while an upload is incomplete.
pub fn upload_fragment_name() -> String {
    format!(
        "{UPLOAD_FRAGMENT_PREFIX}{}{UPLOAD_FRAGMENT_SUFFIX}",
        crate::auth::random_token(18)
    )
}

/// Matches only filenames in VaultLink's private upload-fragment namespace.
pub fn is_upload_fragment_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(token) = name
        .strip_prefix(UPLOAD_FRAGMENT_PREFIX)
        .and_then(|name| name.strip_suffix(UPLOAD_FRAGMENT_SUFFIX))
    else {
        return false;
    };
    token.len() == UPLOAD_FRAGMENT_TOKEN_LENGTH
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub fn deletion_tombstone_name() -> String {
    format!(
        "{DELETION_TOMBSTONE_PREFIX}{}{DELETION_TOMBSTONE_SUFFIX}",
        crate::auth::random_token(18)
    )
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

#[derive(Debug, Eq, PartialEq)]
pub struct DeleteCommitOutcome {
    pub cleanup_pending: bool,
    pub tombstone_path: Option<String>,
}

#[derive(Debug)]
pub enum PublishOutcome {
    Durable,
    PublishedSyncUncertain(io::Error),
}

impl PublishOutcome {
    pub fn is_durable(&self) -> bool {
        matches!(self, Self::Durable)
    }

    pub fn sync_error(&self) -> Option<&io::Error> {
        match self {
            Self::Durable => None,
            Self::PublishedSyncUncertain(error) => Some(error),
        }
    }
}

#[derive(Clone)]
pub struct SecureRoot {
    display_root: PathBuf,
    root: SecureDirectory,
}

/// A descriptor/path capability whose relative operations cannot resolve above this directory.
#[derive(Clone)]
pub struct SecureDirectory {
    #[cfg(target_os = "linux")]
    directory: Arc<File>,
    #[cfg(not(target_os = "linux"))]
    directory: PathBuf,
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

impl DirectoryScanItem {
    pub fn into_entry(self) -> Option<Entry> {
        match self {
            Self::Visible(entry) => Some(entry),
            Self::Filtered => None,
        }
    }
}

/// A continuation-preserving directory iterator. Unlike offset pagination, it
/// never rescans entries that were already consumed.
pub struct DirectoryScan {
    entries: std::fs::ReadDir,
    #[cfg(target_os = "linux")]
    directory: File,
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
    #[cfg(target_os = "linux")]
    visited: HashSet<(u64, u64)>,
    #[cfg(not(target_os = "linux"))]
    visited: HashSet<PathBuf>,
    #[cfg(not(target_os = "linux"))]
    root: PathBuf,
}

#[cfg(target_os = "linux")]
struct CleanupDirectory {
    directory: File,
    entries: std::fs::ReadDir,
    removed_in_pass: bool,
    delete_all: bool,
    remove_from: Option<(File, OsString)>,
}

#[cfg(not(target_os = "linux"))]
struct CleanupDirectory {
    directory: PathBuf,
    entries: std::fs::ReadDir,
    removed_in_pass: bool,
    delete_all: bool,
    remove_from: Option<PathBuf>,
}

pub struct StagedRename {
    original_path: String,
    new_path: String,
    kind: EntryKind,
    committed: bool,
    #[cfg(target_os = "linux")]
    parent: File,
    #[cfg(not(target_os = "linux"))]
    parent: PathBuf,
    original_name: String,
    new_name: String,
}

pub struct StagedDelete {
    original_path: String,
    tombstone_path: String,
    status: EntryStatus,
    committed: bool,
    #[cfg(target_os = "linux")]
    parent: File,
    #[cfg(not(target_os = "linux"))]
    parent: PathBuf,
    original_name: String,
    tombstone_name: String,
}

fn visible_entry(name: OsString, metadata: std::fs::Metadata) -> DirectoryScanItem {
    if is_upload_fragment_name(&name) || is_deletion_tombstone_name(&name) {
        return DirectoryScanItem::Filtered;
    }
    let Some(display_name) = name.to_str() else {
        return DirectoryScanItem::Filtered;
    };
    let Ok(relative) = path_security::validate_relative(display_name) else {
        return DirectoryScanItem::Filtered;
    };
    if relative.components().count() != 1 || (!metadata.is_dir() && !metadata.is_file()) {
        return DirectoryScanItem::Filtered;
    }
    DirectoryScanItem::Visible(Entry {
        name: display_name.to_string(),
        is_dir: metadata.is_dir(),
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

impl Iterator for DirectoryScan {
    type Item = DirectoryScanItem;

    fn next(&mut self) -> Option<Self::Item> {
        let item = match self.entries.next()? {
            Ok(item) => item,
            Err(_) => return Some(DirectoryScanItem::Filtered),
        };
        let name = item.file_name();
        #[cfg(target_os = "linux")]
        {
            let child =
                match linux::openat2(&self.directory, &name, linux::O_PATH | linux::O_NOFOLLOW) {
                    Ok(child) => child,
                    Err(_) => return Some(DirectoryScanItem::Filtered),
                };
            let metadata = match child.metadata() {
                Ok(metadata) => metadata,
                Err(_) => return Some(DirectoryScanItem::Filtered),
            };
            Some(visible_entry(name, metadata))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let metadata = match std::fs::symlink_metadata(item.path()) {
                Ok(metadata) => metadata,
                Err(_) => return Some(DirectoryScanItem::Filtered),
            };
            Some(visible_entry(name, metadata))
        }
    }
}

impl DirectoryScan {
    /// Consumes at most `max_entries` raw directory items and preserves the
    /// continuation for the next call. `entries.len()` can be smaller than
    /// `scanned` when private or unsafe items were filtered.
    pub fn run_batch(&mut self, max_entries: usize) -> io::Result<DirectoryScanBatch> {
        if max_entries == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory scan batch size must be positive",
            ));
        }
        let mut batch = DirectoryScanBatch::default();
        while batch.scanned < max_entries {
            match self.next() {
                Some(item) => {
                    batch.scanned += 1;
                    if let Some(entry) = item.into_entry() {
                        batch.entries.push(entry);
                    }
                }
                None => {
                    batch.complete = true;
                    break;
                }
            }
        }
        Ok(batch)
    }
}

impl UploadFragmentCleanup {
    pub fn run_batch(&mut self, max_entries: usize) -> io::Result<UploadFragmentCleanupBatch> {
        if max_entries == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "upload fragment cleanup batch size must be positive",
            ));
        }
        #[cfg(target_os = "linux")]
        return self.run_linux_batch(max_entries);
        #[cfg(not(target_os = "linux"))]
        return self.run_path_batch(max_entries);
    }

    #[cfg(target_os = "linux")]
    fn run_linux_batch(&mut self, max_entries: usize) -> io::Result<UploadFragmentCleanupBatch> {
        use std::os::unix::fs::MetadataExt;

        let mut batch = UploadFragmentCleanupBatch::default();
        while batch.scanned < max_entries {
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
                    if completed.delete_all {
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
                        match cleanup_directory_from_file(completed.directory) {
                            Ok(directory) => self.directories.push(directory),
                            Err(_) => batch.failed += 1,
                        }
                    }
                    continue;
                }
            };
            batch.scanned += 1;
            let name = item.file_name();
            let child = match linux::openat2(
                &current.directory,
                &name,
                linux::O_PATH | linux::O_NOFOLLOW,
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
                if self.visited.insert((metadata.dev(), metadata.ino())) {
                    match cleanup_directory_from_file(child) {
                        Ok(mut directory) => {
                            let delete_all =
                                current.delete_all || is_deletion_tombstone_name(&name);
                            directory.delete_all = delete_all;
                            if delete_all {
                                directory.remove_from =
                                    Some((current.directory.try_clone()?, name.clone()));
                            }
                            self.directories.push(directory);
                        }
                        Err(_) => batch.failed += 1,
                    }
                }
            } else if current.delete_all
                || (metadata.is_file() && is_upload_fragment_name(&name))
                || is_deletion_tombstone_name(&name)
            {
                if !current.delete_all {
                    let active_key = (metadata.dev(), metadata.ino());
                    let active = active_upload_fragment_guard();
                    if active.contains(&active_key) {
                        continue;
                    }
                }
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

    #[cfg(not(target_os = "linux"))]
    fn run_path_batch(&mut self, max_entries: usize) -> io::Result<UploadFragmentCleanupBatch> {
        let mut batch = UploadFragmentCleanupBatch::default();
        while batch.scanned < max_entries {
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
                    if completed.delete_all {
                        let Some(path) = completed.remove_from else {
                            batch.failed += 1;
                            continue;
                        };
                        match std::fs::remove_dir(path) {
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
                        match cleanup_directory_from_path(completed.directory) {
                            Ok(directory) => self.directories.push(directory),
                            Err(_) => batch.failed += 1,
                        }
                    }
                    continue;
                }
            };
            batch.scanned += 1;
            let path = item.path();
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => {
                    batch.failed += 1;
                    continue;
                }
            };
            if metadata.is_dir() {
                let delete_all =
                    current.delete_all || is_deletion_tombstone_name(&item.file_name());
                let canonical = if delete_all {
                    path.clone()
                } else {
                    match path.canonicalize() {
                        Ok(canonical)
                            if canonical == self.root || canonical.starts_with(&self.root) =>
                        {
                            canonical
                        }
                        Ok(_) => continue,
                        Err(_) => {
                            batch.failed += 1;
                            continue;
                        }
                    }
                };
                if self.visited.insert(canonical.clone()) {
                    match cleanup_directory_from_path(canonical) {
                        Ok(mut directory) => {
                            directory.delete_all = delete_all;
                            if delete_all {
                                directory.remove_from = Some(path);
                            }
                            self.directories.push(directory);
                        }
                        Err(_) => batch.failed += 1,
                    }
                }
            } else if current.delete_all
                || (metadata.is_file() && is_upload_fragment_name(&item.file_name()))
                || is_deletion_tombstone_name(&item.file_name())
            {
                if !current.delete_all {
                    let active = active_upload_fragment_guard();
                    if active.contains(&path) {
                        continue;
                    }
                }
                match std::fs::remove_file(path) {
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

impl SecureRoot {
    pub fn open(path: &Path) -> io::Result<Self> {
        let display_root = path.canonicalize()?;
        if !display_root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "storage root is not a directory",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            let directory = Arc::new(File::open(&display_root)?);
            // Probe the required kernel API at startup and fail with a useful error.
            linux::openat2(
                directory.as_ref(),
                ".",
                linux::O_RDONLY | linux::O_DIRECTORY,
            )?;
            Ok(Self {
                display_root,
                root: SecureDirectory { directory },
            })
        }
        #[cfg(not(target_os = "linux"))]
        Ok(Self {
            root: SecureDirectory {
                directory: display_root.clone(),
            },
            display_root,
        })
    }

    pub fn display_root(&self) -> &Path {
        &self.display_root
    }

    /// Binds a directory share to its own filesystem boundary.
    pub fn bind_directory(&self, relative: &str) -> io::Result<SecureDirectory> {
        self.root.bind_directory(relative)
    }

    /// Opens exactly the configured file-share target without accepting a child path.
    pub fn bind_file(&self, relative: &str) -> io::Result<SecureFile> {
        self.root.open_file(relative)
    }

    /// Compatibility one-shot cleanup. Returns an error when the raw-entry budget
    /// is exhausted before the scan completes; prefer the resumable API below.
    pub fn cleanup_upload_fragments(&self, max_entries: usize) -> io::Result<usize> {
        self.root.cleanup_upload_fragments(max_entries)
    }

    // Global operations remain available for authenticated admin access.
    pub fn open_file(&self, relative: &str) -> io::Result<File> {
        self.root.open_file(relative).map(SecureFile::into_file)
    }

    pub fn metadata(&self, relative: &str) -> io::Result<std::fs::Metadata> {
        self.root.metadata(relative)
    }

    pub fn list(&self, relative: &str, offset: usize, limit: usize) -> io::Result<Vec<Entry>> {
        self.root.list(relative, offset, limit)
    }

    pub fn scan_directory(&self, relative: &str) -> io::Result<DirectoryScan> {
        self.root.scan_directory(relative)
    }

    pub fn entry_status(&self, relative: &str) -> io::Result<EntryStatus> {
        let (parent, name) = split_parent_name(relative)?;
        self.root.bind_directory(&parent)?.entry_status(&name)
    }

    pub fn create_directory(&self, parent: &str, name: &str) -> io::Result<String> {
        let parent = normalized(parent)?;
        let name = path_security::safe_admin_filename(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid directory name"))?;
        self.root.bind_directory(&parent)?.create_directory(name)?;
        Ok(join_relative(&parent, name))
    }

    pub fn stage_rename(&self, relative: &str, new_name: &str) -> io::Result<StagedRename> {
        let (parent_path, original_name) = split_parent_name(relative)?;
        let new_name = path_security::safe_admin_filename(new_name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid destination name"))?;
        if original_name == new_name {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "new name matches current name",
            ));
        }
        let parent = self.root.bind_directory(&parent_path)?;
        let kind = parent.entry_status(&original_name)?.kind;
        parent.rename_noreplace(&original_name, new_name)?;
        Ok(StagedRename {
            original_path: join_relative(&parent_path, &original_name),
            new_path: join_relative(&parent_path, new_name),
            kind,
            committed: false,
            #[cfg(target_os = "linux")]
            parent: parent.directory.try_clone()?,
            #[cfg(not(target_os = "linux"))]
            parent: parent.directory.clone(),
            original_name,
            new_name: new_name.to_string(),
        })
    }

    pub fn stage_delete(&self, relative: &str) -> io::Result<StagedDelete> {
        let (parent_path, original_name) = split_parent_name(relative)?;
        let parent = self.root.bind_directory(&parent_path)?;
        let status = parent.entry_status(&original_name)?;
        let tombstone_name = loop {
            let candidate = deletion_tombstone_name();
            match parent.rename_noreplace(&original_name, &candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        };
        Ok(StagedDelete {
            original_path: join_relative(&parent_path, &original_name),
            tombstone_path: join_relative(&parent_path, &tombstone_name),
            status,
            committed: false,
            #[cfg(target_os = "linux")]
            parent: parent.directory.try_clone()?,
            #[cfg(not(target_os = "linux"))]
            parent: parent.directory.clone(),
            original_name,
            tombstone_name,
        })
    }

    pub fn begin_upload(&self, directory: &str) -> io::Result<PendingUpload> {
        self.root.begin_upload(directory)
    }

    /// Starts a recursive cleanup cursor suitable for bounded background batches.
    /// Uploads active in this process are registered and cannot be removed by it.
    pub fn start_upload_fragment_cleanup(&self) -> io::Result<UploadFragmentCleanup> {
        self.root.start_upload_fragment_cleanup()
    }

    pub fn start_deletion_cleanup(
        &self,
        tombstone_relative: &str,
    ) -> io::Result<UploadFragmentCleanup> {
        let (parent_path, tombstone_name) = split_parent_name_private(tombstone_relative)?;
        if !is_deletion_tombstone_name(OsStr::new(&tombstone_name)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid deletion tombstone",
            ));
        }
        let parent = self.root.bind_directory(&parent_path)?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let directory = linux::openat2(
                parent.directory.as_ref(),
                &tombstone_name,
                linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
            )?;
            let metadata = directory.metadata()?;
            let mut cleanup = cleanup_directory_from_file(directory)?;
            cleanup.delete_all = true;
            cleanup.remove_from = Some((
                parent.directory.as_ref().try_clone()?,
                OsString::from(tombstone_name),
            ));
            return Ok(UploadFragmentCleanup {
                directories: vec![cleanup],
                visited: HashSet::from([(metadata.dev(), metadata.ino())]),
            });
        }
        #[cfg(not(target_os = "linux"))]
        {
            let path = parent.directory.join(tombstone_name);
            let mut cleanup = cleanup_directory_from_path(path.clone())?;
            cleanup.delete_all = true;
            cleanup.remove_from = Some(path.clone());
            Ok(UploadFragmentCleanup {
                directories: vec![cleanup],
                visited: HashSet::from([path]),
                root: self.display_root.clone(),
            })
        }
    }
}

impl SecureDirectory {
    /// Narrows this capability to a child directory. The final component must not be a symlink.
    pub fn bind_directory(&self, relative: &str) -> io::Result<Self> {
        let relative = validated(relative)?;
        #[cfg(target_os = "linux")]
        return Ok(Self {
            directory: Arc::new(linux::openat2(
                self.directory.as_ref(),
                &relative,
                linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
            )?),
        });
        #[cfg(not(target_os = "linux"))]
        {
            let directory = resolve_scoped_existing(&self.directory, &relative)?;
            if !directory.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "share target is not a directory",
                ));
            }
            Ok(Self { directory })
        }
    }

    fn entry_status(&self, name: &str) -> io::Result<EntryStatus> {
        path_security::safe_admin_filename(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid entry name"))?;
        #[cfg(target_os = "linux")]
        {
            let child = linux::openat2(
                self.directory.as_ref(),
                name,
                linux::O_PATH | linux::O_NOFOLLOW,
            )?;
            let metadata = child.metadata()?;
            let kind = if metadata.is_file() {
                EntryKind::File
            } else if metadata.is_dir() {
                EntryKind::Directory
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "entry is not a regular file or directory",
                ));
            };
            let directory_non_empty = if kind == EntryKind::Directory {
                let directory = linux::openat2(
                    self.directory.as_ref(),
                    name,
                    linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
                )?;
                directory_scan_from_file(directory)?
                    .entries
                    .next()
                    .is_some()
            } else {
                false
            };
            return Ok(EntryStatus {
                kind,
                directory_non_empty,
            });
        }
        #[cfg(not(target_os = "linux"))]
        {
            let path = self.directory.join(name);
            let metadata = std::fs::symlink_metadata(&path)?;
            let kind = if metadata.is_file() {
                EntryKind::File
            } else if metadata.is_dir() {
                EntryKind::Directory
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "entry is not a regular file or directory",
                ));
            };
            let directory_non_empty =
                kind == EntryKind::Directory && std::fs::read_dir(path)?.next().is_some();
            Ok(EntryStatus {
                kind,
                directory_non_empty,
            })
        }
    }

    fn create_directory(&self, name: &str) -> io::Result<()> {
        path_security::safe_admin_filename(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid directory name"))?;
        #[cfg(target_os = "linux")]
        {
            linux::mkdir(self.directory.as_ref(), name)?;
            if let Err(error) = self.directory.sync_all() {
                tracing::warn!(%error, "created directory but parent sync was uncertain");
            }
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        {
            std::fs::create_dir(self.directory.join(name))?;
            if let Err(error) = sync_directory_path(&self.directory) {
                tracing::warn!(%error, "created directory but parent sync was uncertain");
            }
            Ok(())
        }
    }

    fn rename_noreplace(&self, old: &str, new: &str) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            linux::rename_noreplace(self.directory.as_ref(), old, new)?;
            if let Err(error) = self.directory.sync_all() {
                tracing::warn!(%error, "renamed entry but parent sync was uncertain");
            }
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        {
            let old = self.directory.join(old);
            let new = self.directory.join(new);
            if new.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "destination already exists",
                ));
            }
            std::fs::rename(old, new)?;
            if let Err(error) = sync_directory_path(&self.directory) {
                tracing::warn!(%error, "renamed entry but parent sync was uncertain");
            }
            Ok(())
        }
    }

    pub fn open_file(&self, relative: &str) -> io::Result<SecureFile> {
        let relative = validated(relative)?;
        #[cfg(target_os = "linux")]
        {
            let probe = linux::openat2(
                self.directory.as_ref(),
                &relative,
                linux::O_PATH | linux::O_NOFOLLOW,
            )?;
            if !probe.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "target is not a regular file",
                ));
            }
            let file = linux::openat2(
                self.directory.as_ref(),
                &relative,
                linux::O_RDONLY | linux::O_NOFOLLOW | linux::O_NONBLOCK,
            )?;
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "target is not a regular file",
                ));
            }
            Ok(SecureFile { file })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let path = resolve_scoped_existing(&self.directory, &relative)?;
            let file = File::open(path)?;
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "target is not a regular file",
                ));
            }
            Ok(SecureFile { file })
        }
    }

    pub fn metadata(&self, relative: &str) -> io::Result<std::fs::Metadata> {
        let relative = validated(relative)?;
        #[cfg(target_os = "linux")]
        return linux::openat2(
            self.directory.as_ref(),
            &relative,
            linux::O_PATH | linux::O_NOFOLLOW,
        )?
        .metadata();
        #[cfg(not(target_os = "linux"))]
        return std::fs::metadata(resolve_scoped_existing(&self.directory, &relative)?);
    }

    pub fn list(&self, relative: &str, offset: usize, limit: usize) -> io::Result<Vec<Entry>> {
        Ok(self
            .scan_directory(relative)?
            .filter_map(DirectoryScanItem::into_entry)
            .skip(offset)
            .take(limit)
            .collect())
    }

    pub fn scan_directory(&self, relative: &str) -> io::Result<DirectoryScan> {
        let relative = validated(relative)?;
        #[cfg(target_os = "linux")]
        {
            let directory = linux::openat2(
                self.directory.as_ref(),
                &relative,
                linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
            )?;
            directory_scan_from_file(directory)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let directory = resolve_scoped_existing(&self.directory, &relative)?;
            directory_scan_from_path(directory)
        }
    }

    pub fn begin_upload(&self, directory: &str) -> io::Result<PendingUpload> {
        let directory = validated(directory)?;
        #[cfg(target_os = "linux")]
        {
            let dir = linux::openat2(
                self.directory.as_ref(),
                &directory,
                linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
            )?;
            PendingUpload::new(dir)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let dir = resolve_scoped_existing(&self.directory, &directory)?;
            if !dir.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "upload target is not a directory",
                ));
            }
            PendingUpload::new(dir)
        }
    }

    /// Compatibility one-shot cleanup. Returns an error when the raw-entry budget
    /// is exhausted before the scan completes; prefer the resumable API below.
    pub fn cleanup_upload_fragments(&self, max_entries: usize) -> io::Result<usize> {
        let mut cleanup = self.start_upload_fragment_cleanup()?;
        let batch = cleanup.run_batch(max_entries)?;
        if batch.complete {
            Ok(batch.removed)
        } else {
            Err(io::Error::other(
                "upload fragment cleanup entry limit exceeded",
            ))
        }
    }

    /// Starts a recursive cleanup cursor suitable for bounded background batches.
    /// Uploads active in this process are registered and cannot be removed by it.
    pub fn start_upload_fragment_cleanup(&self) -> io::Result<UploadFragmentCleanup> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;

            let root = self.directory.try_clone()?;
            let metadata = root.metadata()?;
            let directory = cleanup_directory_from_file(root)?;
            Ok(UploadFragmentCleanup {
                directories: vec![directory],
                visited: HashSet::from([(metadata.dev(), metadata.ino())]),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let root = self.directory.canonicalize()?;
            let directory = cleanup_directory_from_path(root.clone())?;
            Ok(UploadFragmentCleanup {
                directories: vec![directory],
                visited: HashSet::from([root.clone()]),
                root,
            })
        }
    }
}

impl SecureFile {
    pub fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.file.metadata()
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

#[cfg(not(target_os = "linux"))]
fn resolve_scoped_existing(root: &Path, raw: &str) -> io::Result<PathBuf> {
    let relative = validated(raw)?;
    let target = root.join(relative);
    let metadata = std::fs::symlink_metadata(&target)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "final symlink is not allowed",
        ));
    }
    let canonical = target.canonicalize()?;
    if canonical == root || canonical.starts_with(root) {
        Ok(canonical)
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "path is outside the secure directory",
        ))
    }
}

#[cfg(target_os = "linux")]
fn directory_scan_from_file(directory: File) -> io::Result<DirectoryScan> {
    use std::os::fd::AsRawFd;

    let proc_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let entries = std::fs::read_dir(proc_path)?;
    Ok(DirectoryScan { entries, directory })
}

#[cfg(not(target_os = "linux"))]
fn directory_scan_from_path(directory: PathBuf) -> io::Result<DirectoryScan> {
    Ok(DirectoryScan {
        entries: std::fs::read_dir(directory)?,
    })
}

#[cfg(target_os = "linux")]
fn cleanup_directory_from_file(directory: File) -> io::Result<CleanupDirectory> {
    use std::os::fd::AsRawFd;

    let proc_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let entries = std::fs::read_dir(proc_path)?;
    Ok(CleanupDirectory {
        directory,
        entries,
        removed_in_pass: false,
        delete_all: false,
        remove_from: None,
    })
}

#[cfg(not(target_os = "linux"))]
fn cleanup_directory_from_path(directory: PathBuf) -> io::Result<CleanupDirectory> {
    Ok(CleanupDirectory {
        entries: std::fs::read_dir(&directory)?,
        directory,
        removed_in_pass: false,
        delete_all: false,
        remove_from: None,
    })
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

fn upload_destination_name(name: &str) -> io::Result<&str> {
    path_security::safe_admin_filename(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "upload destination uses an invalid or private name",
        )
    })
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

    pub fn commit(mut self) {
        self.committed = true;
    }

    fn rollback(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            linux::rename_noreplace(&self.parent, &self.new_name, &self.original_name)?;
            if let Err(error) = self.parent.sync_all() {
                tracing::warn!(%error, "rolled back rename but parent sync was uncertain");
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            std::fs::rename(
                self.parent.join(&self.new_name),
                self.parent.join(&self.original_name),
            )?;
            if let Err(error) = sync_directory_path(&self.parent) {
                tracing::warn!(%error, "rolled back rename but parent sync was uncertain");
            }
            Ok(())
        }
    }
}

impl Drop for StagedRename {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(error) = self.rollback() {
                tracing::error!(%error, from = %self.new_path, to = %self.original_path, "could not roll back staged rename");
            }
        }
    }
}

impl StagedDelete {
    pub fn original_path(&self) -> &str {
        &self.original_path
    }

    pub fn status(&self) -> &EntryStatus {
        &self.status
    }

    pub fn commit(mut self) -> io::Result<DeleteCommitOutcome> {
        if self.status.kind == EntryKind::Directory && self.status.directory_non_empty {
            self.committed = true;
            return Ok(DeleteCommitOutcome {
                cleanup_pending: true,
                tombstone_path: Some(self.tombstone_path.clone()),
            });
        }
        self.committed = true;
        #[cfg(target_os = "linux")]
        let removal = match self.status.kind {
            EntryKind::File => linux::unlink(&self.parent, OsStr::new(&self.tombstone_name)),
            EntryKind::Directory => linux::rmdir(&self.parent, OsStr::new(&self.tombstone_name)),
        };
        #[cfg(not(target_os = "linux"))]
        let removal = {
            let tombstone = self.parent.join(&self.tombstone_name);
            match self.status.kind {
                EntryKind::File => std::fs::remove_file(tombstone),
                EntryKind::Directory => std::fs::remove_dir(tombstone),
            }
        };
        if let Err(error) = removal {
            tracing::warn!(%error, tombstone = %self.tombstone_path, "deletion tombstone cleanup deferred");
            return Ok(DeleteCommitOutcome {
                cleanup_pending: true,
                tombstone_path: Some(self.tombstone_path.clone()),
            });
        }
        #[cfg(target_os = "linux")]
        if let Err(error) = self.parent.sync_all() {
            tracing::warn!(%error, "removed deletion tombstone but parent sync was uncertain");
        }
        #[cfg(not(target_os = "linux"))]
        if let Err(error) = sync_directory_path(&self.parent) {
            tracing::warn!(%error, "removed deletion tombstone but parent sync was uncertain");
        }
        Ok(DeleteCommitOutcome {
            cleanup_pending: false,
            tombstone_path: None,
        })
    }

    fn rollback(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            linux::rename_noreplace(&self.parent, &self.tombstone_name, &self.original_name)?;
            if let Err(error) = self.parent.sync_all() {
                tracing::warn!(%error, "restored deletion target but parent sync was uncertain");
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            std::fs::rename(
                self.parent.join(&self.tombstone_name),
                self.parent.join(&self.original_name),
            )?;
            if let Err(error) = sync_directory_path(&self.parent) {
                tracing::warn!(%error, "restored deletion target but parent sync was uncertain");
            }
            Ok(())
        }
    }
}

impl Drop for StagedDelete {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(error) = self.rollback() {
                tracing::error!(%error, tombstone = %self.tombstone_path, original = %self.original_path, "could not roll back staged deletion");
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub struct PendingUpload {
    directory: File,
    temporary_name: String,
    file: Option<File>,
    active_key: Option<ActiveUploadFragmentKey>,
    published: bool,
    #[cfg(test)]
    next_directory_sync_error: Option<io::ErrorKind>,
}

#[cfg(target_os = "linux")]
impl PendingUpload {
    fn new(directory: File) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let mut active = active_upload_fragment_guard();
        for _ in 0..16 {
            let temporary_name = upload_fragment_name();
            match linux::openat2(
                &directory,
                &temporary_name,
                linux::O_WRONLY | linux::O_CREAT | linux::O_EXCL,
            ) {
                Ok(file) => {
                    let metadata = match file.metadata() {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            drop(file);
                            let _ = linux::unlink(&directory, &temporary_name);
                            return Err(error);
                        }
                    };
                    let active_key = (metadata.dev(), metadata.ino());
                    active.insert(active_key);
                    return Ok(Self {
                        directory,
                        temporary_name,
                        file: Some(file),
                        active_key: Some(active_key),
                        published: false,
                        #[cfg(test)]
                        next_directory_sync_error: None,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate upload temporary file",
        ))
    }
    pub fn take_file(&mut self) -> io::Result<File> {
        self.file
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "upload file already taken"))
    }

    pub fn publish(&mut self, name: &str) -> io::Result<PublishOutcome> {
        let name = upload_destination_name(name)?;
        linux::rename_noreplace(&self.directory, &self.temporary_name, name)?;
        Ok(self.finish_publication())
    }

    pub fn publish_replace(&mut self, name: &str) -> io::Result<PublishOutcome> {
        let name = upload_destination_name(name)?;
        linux::rename_replace(&self.directory, &self.temporary_name, name)?;
        Ok(self.finish_publication())
    }

    fn finish_publication(&mut self) -> PublishOutcome {
        // renameat2 has already made the destination visible. Drop must not try to
        // unlink the now-nonexistent temporary name even when directory fsync fails.
        self.published = true;
        if let Some(active_key) = self.active_key.take() {
            unregister_upload_fragment(&active_key);
        }
        match self.sync_directory() {
            Ok(()) => PublishOutcome::Durable,
            Err(error) => PublishOutcome::PublishedSyncUncertain(error),
        }
    }

    fn sync_directory(&mut self) -> io::Result<()> {
        #[cfg(test)]
        if let Some(kind) = self.next_directory_sync_error.take() {
            return Err(io::Error::new(kind, "injected directory sync failure"));
        }
        self.directory.sync_all()
    }

    #[cfg(test)]
    pub(crate) fn fail_next_directory_sync(&mut self, kind: io::ErrorKind) {
        self.next_directory_sync_error = Some(kind);
    }
}

#[cfg(target_os = "linux")]
impl Drop for PendingUpload {
    fn drop(&mut self) {
        let mut active = active_upload_fragment_guard();
        if let Some(active_key) = self.active_key.take() {
            active.remove(&active_key);
        }
        if !self.published {
            let _ = linux::unlink(&self.directory, &self.temporary_name);
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub struct PendingUpload {
    temporary: Option<tempfile::NamedTempFile>,
    directory: PathBuf,
    active_key: Option<ActiveUploadFragmentKey>,
    #[cfg(test)]
    next_reopen_error: Option<io::ErrorKind>,
    #[cfg(test)]
    next_directory_sync_error: Option<io::ErrorKind>,
}

#[cfg(not(target_os = "linux"))]
impl PendingUpload {
    fn new(directory: PathBuf) -> io::Result<Self> {
        let mut active = active_upload_fragment_guard();
        let temporary = tempfile::Builder::new()
            .prefix(UPLOAD_FRAGMENT_PREFIX)
            .suffix(UPLOAD_FRAGMENT_SUFFIX)
            .rand_bytes(UPLOAD_FRAGMENT_TOKEN_LENGTH)
            .tempfile_in(&directory)?;
        let active_key = temporary.path().to_path_buf();
        active.insert(active_key.clone());
        Ok(Self {
            temporary: Some(temporary),
            directory,
            active_key: Some(active_key),
            #[cfg(test)]
            next_reopen_error: None,
            #[cfg(test)]
            next_directory_sync_error: None,
        })
    }
    pub fn take_file(&mut self) -> io::Result<File> {
        #[cfg(test)]
        if let Some(kind) = self.next_reopen_error.take() {
            return Err(io::Error::new(kind, "injected upload reopen failure"));
        }
        self.temporary
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "upload file already taken")
            })?
            .reopen()
    }
    pub fn publish(&mut self, name: &str) -> io::Result<PublishOutcome> {
        let name = upload_destination_name(name)?;
        let temporary = self.temporary.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "upload already published")
        })?;
        let persisted = temporary
            .persist_noclobber(self.directory.join(name))
            .map_err(|error| error.error)?;
        drop(persisted);
        Ok(self.finish_publication())
    }

    pub fn publish_replace(&mut self, name: &str) -> io::Result<PublishOutcome> {
        let name = upload_destination_name(name)?;
        let temporary = self.temporary.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "upload already published")
        })?;
        let persisted = temporary
            .persist(self.directory.join(name))
            .map_err(|error| error.error)?;
        drop(persisted);
        Ok(self.finish_publication())
    }

    fn finish_publication(&mut self) -> PublishOutcome {
        if let Some(active_key) = self.active_key.take() {
            unregister_upload_fragment(&active_key);
        }
        match self.sync_directory() {
            Ok(()) => PublishOutcome::Durable,
            Err(error) => PublishOutcome::PublishedSyncUncertain(error),
        }
    }

    fn sync_directory(&mut self) -> io::Result<()> {
        #[cfg(test)]
        if let Some(kind) = self.next_directory_sync_error.take() {
            return Err(io::Error::new(kind, "injected directory sync failure"));
        }
        sync_directory_path(&self.directory)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_reopen(&mut self, kind: io::ErrorKind) {
        self.next_reopen_error = Some(kind);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_directory_sync(&mut self, kind: io::ErrorKind) {
        self.next_directory_sync_error = Some(kind);
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for PendingUpload {
    fn drop(&mut self) {
        let mut active = active_upload_fragment_guard();
        if let Some(active_key) = self.active_key.take() {
            active.remove(&active_key);
        }
        drop(self.temporary.take());
    }
}

#[cfg(all(not(target_os = "linux"), windows))]
fn sync_directory_path(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?
        .sync_all()
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn sync_directory_path(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        ffi::CString,
        fs::File,
        io,
        os::unix::ffi::OsStrExt,
        os::{
            fd::{AsRawFd, FromRawFd},
            raw::{c_char, c_int, c_long, c_uint},
        },
        path::Path,
    };

    pub const O_RDONLY: u64 = 0;
    pub const O_WRONLY: u64 = 1;
    pub const O_CREAT: u64 = 0o100;
    pub const O_EXCL: u64 = 0o200;
    pub const O_NONBLOCK: u64 = 0o4000;
    pub const O_NOFOLLOW: u64 = 0o400000;
    pub const O_DIRECTORY: u64 = 0o200000;
    pub const O_PATH: u64 = 0o10000000;
    const O_CLOEXEC: u64 = 0o2000000;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_BENEATH: u64 = 0x08;
    const RENAME_NOREPLACE: c_uint = 1;
    const AT_REMOVEDIR: c_int = 0x200;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    extern "C" {
        fn syscall(number: c_long, ...) -> c_long;
        fn renameat2(
            old_dir: c_int,
            old: *const c_char,
            new_dir: c_int,
            new: *const c_char,
            flags: c_uint,
        ) -> c_int;
        fn unlinkat(dir: c_int, path: *const c_char, flags: c_int) -> c_int;
        fn mkdirat(dir: c_int, path: *const c_char, mode: c_uint) -> c_int;
    }

    #[cfg(target_arch = "x86_64")]
    const SYS_OPENAT2: c_long = 437;
    #[cfg(not(target_arch = "x86_64"))]
    compile_error!("VaultLink Linux builds support amd64 only");

    fn c_path(path: impl AsRef<Path>) -> io::Result<CString> {
        CString::new(path.as_ref().as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
    }

    pub fn openat2(directory: &File, path: impl AsRef<Path>, flags: u64) -> io::Result<File> {
        let path = c_path(path)?;
        let how = OpenHow {
            flags: flags | O_CLOEXEC,
            mode: if flags & O_CREAT != 0 { 0o600 } else { 0 },
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
        };
        // SAFETY: pointers refer to initialized values for the duration of the syscall.
        let fd = unsafe {
            syscall(
                SYS_OPENAT2,
                directory.as_raw_fd(),
                path.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful openat2 returns a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd as c_int) })
    }

    pub fn rename_noreplace(directory: &File, old: &str, new: &str) -> io::Result<()> {
        let old = c_path(old)?;
        let new = c_path(new)?;
        // SAFETY: both C strings and the directory descriptor are valid.
        let result = unsafe {
            renameat2(
                directory.as_raw_fd(),
                old.as_ptr(),
                directory.as_raw_fd(),
                new.as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn rename_replace(directory: &File, old: &str, new: &str) -> io::Result<()> {
        let old = c_path(old)?;
        let new = c_path(new)?;
        // SAFETY: both C strings and the directory descriptor are valid. flags=0 is atomic
        // same-directory rename and replaces an existing non-directory destination.
        let result = unsafe {
            renameat2(
                directory.as_raw_fd(),
                old.as_ptr(),
                directory.as_raw_fd(),
                new.as_ptr(),
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn unlink(directory: &File, name: impl AsRef<Path>) -> io::Result<()> {
        let name = c_path(name)?;
        // SAFETY: C string and descriptor are valid; flags=0 removes files only.
        let result = unsafe { unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn rmdir(directory: &File, name: impl AsRef<Path>) -> io::Result<()> {
        let name = c_path(name)?;
        // SAFETY: C string and descriptor are valid; AT_REMOVEDIR refuses non-directories.
        let result = unsafe { unlinkat(directory.as_raw_fd(), name.as_ptr(), AT_REMOVEDIR) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn mkdir(directory: &File, name: impl AsRef<Path>) -> io::Result<()> {
        let name = c_path(name)?;
        // SAFETY: C string and descriptor are valid; mode is intentionally admin-private.
        let result = unsafe { mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
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

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn pending_upload_reopen_and_reuse_fail_without_panicking() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();

        let mut missing = root.begin_upload("").unwrap();
        missing.fail_next_reopen(io::ErrorKind::Other);
        assert_eq!(
            missing.take_file().unwrap_err().kind(),
            io::ErrorKind::Other
        );

        let mut published = root.begin_upload("").unwrap();
        published.publish("published.txt").unwrap();
        assert_eq!(
            published.take_file().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            published.publish("again.txt").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
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
            .commit();
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
        let outcome = staged.commit().unwrap();
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
        assert!(std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none());
    }

    #[test]
    fn cleanup_removes_only_regular_upload_fragments_recursively() {
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let first = upload_fragment_name();
        let second = upload_fragment_name();
        std::fs::write(directory.path().join(&first), b"partial").unwrap();
        std::fs::write(nested.join(&second), b"partial").unwrap();
        std::fs::write(directory.path().join("keep.part"), b"keep").unwrap();
        let matching_directory = upload_fragment_name();
        std::fs::create_dir(directory.path().join(&matching_directory)).unwrap();

        let root = SecureRoot::open(directory.path()).unwrap();
        assert_eq!(root.cleanup_upload_fragments(100).unwrap(), 2);
        assert!(!directory.path().join(first).exists());
        assert!(!nested.join(second).exists());
        assert_eq!(
            std::fs::read(directory.path().join("keep.part")).unwrap(),
            b"keep"
        );
        assert!(directory.path().join(matching_directory).is_dir());
    }

    #[test]
    fn cleanup_stops_at_the_configured_scan_bound() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("one.txt"), b"one").unwrap();
        std::fs::write(directory.path().join("two.txt"), b"two").unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        assert!(root.cleanup_upload_fragments(1).is_err());
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
        assert_eq!(scanned, 2);
        assert_eq!(names, vec!["visible.txt"]);
    }

    #[test]
    fn cleanup_continues_across_strictly_bounded_batches() {
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let mut fragments = Vec::new();
        for index in 0usize..16 {
            let fragment = upload_fragment_name();
            let parent = if index.is_multiple_of(2) {
                directory.path()
            } else {
                &nested
            };
            std::fs::write(parent.join(&fragment), b"partial").unwrap();
            std::fs::write(parent.join(format!("keep-{index}.txt")), b"keep").unwrap();
            fragments.push(parent.join(fragment));
        }
        let root = SecureRoot::open(directory.path()).unwrap();
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
        assert!(directory.path().join("keep-0.txt").is_file());
        assert!(nested.join("keep-1.txt").is_file());
    }

    #[test]
    fn cleanup_serializes_creation_and_active_registration() {
        #[cfg(target_os = "linux")]
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        let fragment = upload_fragment_name();
        let fragment_path = directory.path().join(fragment);

        // This is the same critical section used by PendingUpload: while the
        // fragment becomes visible but is not registered yet, cleanup cannot
        // perform its check-and-unlink section.
        let mut active = active_upload_fragment_guard();
        std::fs::write(&fragment_path, b"active").unwrap();
        #[cfg(target_os = "linux")]
        let active_key = {
            let metadata = std::fs::metadata(&fragment_path).unwrap();
            (metadata.dev(), metadata.ino())
        };
        #[cfg(not(target_os = "linux"))]
        let active_key = fragment_path.canonicalize().unwrap();

        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let cleanup_thread = std::thread::spawn(move || {
            let mut cleanup = root.start_upload_fragment_cleanup().unwrap();
            started_sender.send(()).unwrap();
            let mut removed = 0usize;
            loop {
                let batch = cleanup.run_batch(1).unwrap();
                removed += batch.removed;
                if batch.complete {
                    return removed;
                }
            }
        });
        started_receiver.recv().unwrap();
        #[cfg(target_os = "linux")]
        active.insert(active_key);
        #[cfg(not(target_os = "linux"))]
        active.insert(active_key.clone());
        drop(active);

        assert_eq!(cleanup_thread.join().unwrap(), 0);
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

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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
        let remaining_parts = std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".part"))
            .count();
        assert_eq!(remaining_parts, 0);
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
        let names: Vec<_> = std::fs::read_dir(directory.path())
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

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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
