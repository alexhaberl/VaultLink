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

use std::sync::Arc;

use crate::path_security;

const UPLOAD_FRAGMENT_PREFIX: &str = ".vaultlink-";
const UPLOAD_FRAGMENT_SUFFIX: &str = ".part";
const UPLOAD_FRAGMENT_TOKEN_LENGTH: usize = 24;
const DELETION_TOMBSTONE_PREFIX: &str = ".vaultlink-delete-";
const DELETION_TOMBSTONE_SUFFIX: &str = ".tombstone";
const DELETION_TOMBSTONE_TOKEN_LENGTH: usize = 24;
const DELETION_PENDING_PREFIX: &str = ".vaultlink-delete-pending-";
const DELETION_PENDING_SUFFIX: &str = ".pending";
const DELETION_MANIFEST_SUFFIX: &str = ".manifest";
const INTERNAL_DIRECTORY_NAME: &str = path_security::INTERNAL_STORAGE_DIRECTORY_NAME;
const UPLOAD_STAGING_DIRECTORY_NAME: &str = "uploads";
const TOMBSTONE_STAGING_DIRECTORY_NAME: &str = "tombstones";

type ActiveUploadFragmentKey = String;

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
    tombstones: Arc<File>,
    #[cfg(test)]
    next_delete_staging_rename_error: Arc<Mutex<Option<io::ErrorKind>>>,
    #[cfg(test)]
    next_delete_promotion_rename_error: Arc<Mutex<Option<io::ErrorKind>>>,
}

/// A descriptor/path capability whose relative operations cannot resolve above this directory.
#[derive(Clone)]
pub struct SecureDirectory {
    directory: Arc<File>,
    staging: Arc<File>,
    forbid_symlinks: bool,
    allow_replace: bool,
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
}

struct CleanupDirectory {
    directory: File,
    entries: std::fs::ReadDir,
    removed_in_pass: bool,
    policy: CleanupPolicy,
    remove_from: Option<(File, OsString)>,
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
    committed: bool,
    parent: File,
    original_name: String,
    new_name: String,
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
    active_key: Option<ActiveUploadFragmentKey>,
    #[cfg(test)]
    next_promotion_rename_error: Arc<Mutex<Option<io::ErrorKind>>>,
}

fn visible_entry(name: OsString, metadata: std::fs::Metadata) -> DirectoryScanItem {
    if path_security::is_internal_storage_name(&name)
        || is_upload_fragment_name(&name)
        || is_deletion_tombstone_name(&name)
    {
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
        let child = match linux::openat2_scoped(
            &self.directory,
            &name,
            linux::O_PATH | linux::O_NOFOLLOW,
            self.strict_mount_boundary,
        ) {
            Ok(child) => child,
            Err(_) => return Some(DirectoryScanItem::Filtered),
        };
        let metadata = match child.metadata() {
            Ok(metadata) => metadata,
            Err(_) => return Some(DirectoryScanItem::Filtered),
        };
        Some(visible_entry(name, metadata))
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
        self.run_linux_batch(max_entries)
    }

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
                    if completed.policy == CleanupPolicy::DeleteAll {
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
                        match cleanup_directory_from_file(completed.directory, completed.policy) {
                            Ok(directory) => self.directories.push(directory),
                            Err(_) => batch.failed += 1,
                        }
                    }
                    continue;
                }
            };
            batch.scanned += 1;
            let name = item.file_name();
            if current.policy == CleanupPolicy::TombstoneRoot && is_deletion_pending_name(&name) {
                continue;
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
                    if self.visited.insert((metadata.dev(), metadata.ino())) {
                        match cleanup_directory_from_file(child, child_policy) {
                            Ok(mut directory) => {
                                directory.remove_from =
                                    Some((current.directory.try_clone()?, name.clone()));
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

fn write_pending_manifest(
    staging: &File,
    pending_name: &str,
    original_path: &str,
) -> io::Result<String> {
    use std::io::Write;

    let manifest_name = deletion_manifest_name(pending_name);
    let mut manifest = linux::openat2(
        staging,
        &manifest_name,
        linux::O_WRONLY | linux::O_CREAT | linux::O_EXCL,
    )?;
    let result = (|| {
        serde_json::to_writer(&mut manifest, original_path).map_err(io::Error::other)?;
        manifest.write_all(b"\n")?;
        manifest.sync_all()?;
        staging.sync_all()
    })();
    if result.is_err() {
        drop(manifest);
        let _ = linux::unlink(staging, &manifest_name);
        let _ = staging.sync_all();
    }
    result.map(|()| manifest_name)
}

fn read_pending_manifest(staging: &File, manifest_name: &str) -> io::Result<String> {
    use std::io::Read;

    const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
    let mut manifest = linux::openat2(staging, manifest_name, linux::O_RDONLY | linux::O_NOFOLLOW)?;
    let metadata = manifest.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "deletion recovery manifest is not a small regular file",
        ));
    }
    let mut content = Vec::with_capacity(metadata.len() as usize);
    manifest
        .by_ref()
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut content)?;
    if content.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "deletion recovery manifest exceeds its size limit",
        ));
    }
    serde_json::from_slice(&content).map_err(io::Error::other)
}

fn remove_pending_manifest(staging: &File, manifest_name: &str) -> io::Result<()> {
    match linux::unlink(staging, manifest_name) {
        Ok(()) => staging.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn entry_matches_identity(
    directory: &File,
    name: &str,
    expected: (u64, u64),
    expected_kind: EntryKind,
) -> bool {
    use std::os::unix::fs::MetadataExt;

    linux::openat2(directory, name, linux::O_PATH | linux::O_NOFOLLOW)
        .and_then(|entry| entry.metadata())
        .is_ok_and(|metadata| {
            (metadata.dev(), metadata.ino()) == expected
                && match expected_kind {
                    EntryKind::File => metadata.is_file(),
                    EntryKind::Directory => metadata.is_dir(),
                }
        })
}

fn rollback_pending_delete(
    staging: &File,
    pending_name: &str,
    manifest_name: &str,
    parent: &File,
    original_name: &str,
    original_path: &str,
) {
    match linux::rename_noreplace_between(staging, pending_name, parent, original_name) {
        Ok(()) => {
            let staging_sync = staging.sync_all();
            let parent_sync = parent.sync_all();
            if let Err(error) = &staging_sync {
                tracing::warn!(%error, "rolled back pending deletion but staging sync was uncertain");
            }
            if let Err(error) = &parent_sync {
                tracing::warn!(%error, "rolled back pending deletion but source sync was uncertain");
            }
            if staging_sync.is_ok() && parent_sync.is_ok() {
                if let Err(error) = remove_pending_manifest(staging, manifest_name) {
                    tracing::warn!(%error, manifest = %manifest_name, "could not remove durable rollback manifest");
                }
            }
        }
        Err(error) => {
            tracing::error!(
                %error,
                recovery_entry = %pending_name,
                original = %original_path,
                "could not roll back pending deletion; private recovery entry was preserved"
            );
        }
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
        let display_root = path.canonicalize()?;
        if !display_root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "storage root is not a directory",
            ));
        }
        let directory = Arc::new(File::open(&display_root)?);
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
        let internal = Arc::new(open_private_directory(
            &internal_parent,
            internal_name,
            !require_preprovisioned_internal,
        )?);
        let canonical_internal = internal_path.canonicalize()?;
        if require_preprovisioned_internal
            && (canonical_internal.starts_with(&display_root)
                || display_root.starts_with(&canonical_internal))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "external-writer internal storage must be outside the user-visible storage root",
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
        let secure_root = Self {
            display_root,
            root: SecureDirectory {
                directory,
                staging: uploads,
                forbid_symlinks: forbid_user_symlinks,
                allow_replace: !forbid_user_symlinks,
            },
            tombstones,
            #[cfg(test)]
            next_delete_staging_rename_error: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            next_delete_promotion_rename_error: Arc::new(Mutex::new(None)),
        };
        secure_root.recover_pending_deletions()?;
        Ok(secure_root)
    }

    pub fn display_root(&self) -> &Path {
        &self.display_root
    }

    fn recover_pending_deletions(&self) -> io::Result<()> {
        use std::os::fd::AsRawFd;

        let proc_path = format!("/proc/self/fd/{}", self.tombstones.as_ref().as_raw_fd());
        for item in std::fs::read_dir(proc_path)? {
            let item = item?;
            let pending_name = item.file_name();
            if !is_deletion_pending_name(&pending_name) {
                continue;
            }
            let Some(pending_name) = pending_name.to_str() else {
                continue;
            };
            let manifest_name = deletion_manifest_name(pending_name);
            let original_path = match read_pending_manifest(
                self.tombstones.as_ref(),
                &manifest_name,
            ) {
                Ok(path) => path,
                Err(error) => {
                    tracing::error!(%error, recovery_entry = %pending_name, manifest = %manifest_name, "pending deletion has no valid recovery manifest; entry was preserved");
                    continue;
                }
            };
            let (parent_path, original_name) = match split_parent_name(&original_path) {
                Ok(parts) => parts,
                Err(error) => {
                    tracing::error!(%error, recovery_entry = %pending_name, original = %original_path, "pending deletion manifest has an invalid original path; entry was preserved");
                    continue;
                }
            };
            let parent = match self.root.bind_directory(&parent_path) {
                Ok(parent) => parent,
                Err(error) => {
                    tracing::error!(%error, recovery_entry = %pending_name, original = %original_path, "pending deletion parent is unavailable; entry was preserved");
                    continue;
                }
            };
            match linux::rename_noreplace_between(
                self.tombstones.as_ref(),
                pending_name,
                parent.directory.as_ref(),
                &original_name,
            ) {
                Ok(()) => {
                    self.tombstones.sync_all()?;
                    parent.directory.sync_all()?;
                    if let Err(error) =
                        remove_pending_manifest(self.tombstones.as_ref(), &manifest_name)
                    {
                        tracing::warn!(%error, manifest = %manifest_name, "could not remove recovered deletion manifest");
                    }
                    tracing::warn!(recovery_entry = %pending_name, original = %original_path, "restored uncommitted deletion after restart");
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    tracing::error!(%error, recovery_entry = %pending_name, original = %original_path, "could not restore uncommitted deletion because a co-writer reused the original path; both objects were preserved");
                }
                Err(error) => {
                    tracing::error!(%error, recovery_entry = %pending_name, original = %original_path, "could not restore uncommitted deletion; recovery entry was preserved");
                }
            }
        }
        Ok(())
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
        if let Err(error) = parent.rename_noreplace(&original_name, new_name) {
            if entry_matches_identity(parent.directory.as_ref(), new_name, source_identity, kind) {
                tracing::warn!(%error, from = %original_path, to = %new_name, "rename returned an error after the entry moved; continuing with verified identity");
            } else {
                return Err(error);
            }
        }
        Ok(StagedRename {
            original_path,
            new_path: join_relative(&parent_path, new_name),
            kind,
            committed: false,
            parent: transaction_parent,
            original_name,
            new_name: new_name.to_string(),
        })
    }

    pub fn stage_delete(&self, relative: &str) -> io::Result<StagedDelete> {
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
        let (tombstone_name, manifest_name) = loop {
            let candidate = deletion_pending_name();
            // Register before any staging I/O. Cleanup can never observe the
            // renamed pending entry before its active name is published.
            if !active_upload_fragment_guard().insert(candidate.clone()) {
                continue;
            }
            let manifest_name = match write_pending_manifest(
                self.tombstones.as_ref(),
                &candidate,
                &original_path,
            ) {
                Ok(name) => name,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    unregister_upload_fragment(&candidate);
                    continue;
                }
                Err(error) => {
                    unregister_upload_fragment(&candidate);
                    return Err(error);
                }
            };
            let rename = linux::rename_noreplace_between(
                parent.directory.as_ref(),
                &original_name,
                self.tombstones.as_ref(),
                &candidate,
            );
            #[cfg(test)]
            let rename = inject_error_after_successful_rename(
                rename,
                self.next_delete_staging_rename_error.as_ref(),
            );
            match rename {
                Ok(()) => break (candidate, manifest_name),
                Err(error) => {
                    if entry_matches_identity(
                        self.tombstones.as_ref(),
                        &candidate,
                        source_identity,
                        source_kind,
                    ) {
                        tracing::warn!(%error, pending = %candidate, original = %original_path, "delete staging rename returned an error after the source became pending; continuing with verified identity");
                        break (candidate, manifest_name);
                    }
                    let source_unchanged = entry_matches_identity(
                        parent.directory.as_ref(),
                        &original_name,
                        source_identity,
                        source_kind,
                    );
                    if source_unchanged {
                        if let Err(cleanup_error) =
                            remove_pending_manifest(self.tombstones.as_ref(), &manifest_name)
                        {
                            tracing::warn!(%cleanup_error, manifest = %manifest_name, "could not remove unused deletion manifest");
                        }
                        unregister_upload_fragment(&candidate);
                        if error.kind() == io::ErrorKind::AlreadyExists {
                            continue;
                        }
                    } else {
                        tracing::error!(%error, recovery_entry = %candidate, manifest = %manifest_name, original = %original_path, "delete staging rename outcome is ambiguous; recovery metadata was preserved");
                    }
                    return Err(error);
                }
            }
        };
        let active_key = tombstone_name.clone();
        let tombstone = match linux::openat2(
            self.tombstones.as_ref(),
            &tombstone_name,
            linux::O_PATH | linux::O_NOFOLLOW,
        ) {
            Ok(file) => file,
            Err(error) => {
                rollback_pending_delete(
                    self.tombstones.as_ref(),
                    &tombstone_name,
                    &manifest_name,
                    parent.directory.as_ref(),
                    &original_name,
                    &original_path,
                );
                unregister_upload_fragment(&active_key);
                return Err(error);
            }
        };
        let tombstone_metadata = match tombstone.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                rollback_pending_delete(
                    self.tombstones.as_ref(),
                    &tombstone_name,
                    &manifest_name,
                    parent.directory.as_ref(),
                    &original_name,
                    &original_path,
                );
                unregister_upload_fragment(&active_key);
                return Err(error);
            }
        };
        if (tombstone_metadata.dev(), tombstone_metadata.ino()) != source_identity
            || tombstone_metadata.is_dir() != source_metadata.is_dir()
            || tombstone_metadata.is_file() != source_metadata.is_file()
        {
            rollback_pending_delete(
                self.tombstones.as_ref(),
                &tombstone_name,
                &manifest_name,
                parent.directory.as_ref(),
                &original_name,
                &original_path,
            );
            unregister_upload_fragment(&active_key);
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
            let directory = match linux::openat2(
                self.tombstones.as_ref(),
                &tombstone_name,
                linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
            ) {
                Ok(directory) => directory,
                Err(error) => {
                    rollback_pending_delete(
                        self.tombstones.as_ref(),
                        &tombstone_name,
                        &manifest_name,
                        parent.directory.as_ref(),
                        &original_name,
                        &original_path,
                    );
                    unregister_upload_fragment(&active_key);
                    return Err(error);
                }
            };
            let mut scan = match directory_scan_from_file(directory, false) {
                Ok(scan) => scan,
                Err(error) => {
                    rollback_pending_delete(
                        self.tombstones.as_ref(),
                        &tombstone_name,
                        &manifest_name,
                        parent.directory.as_ref(),
                        &original_name,
                        &original_path,
                    );
                    unregister_upload_fragment(&active_key);
                    return Err(error);
                }
            };
            EntryStatus {
                kind: EntryKind::Directory,
                directory_non_empty: scan.entries.next().is_some(),
            }
        } else {
            rollback_pending_delete(
                self.tombstones.as_ref(),
                &tombstone_name,
                &manifest_name,
                parent.directory.as_ref(),
                &original_name,
                &original_path,
            );
            unregister_upload_fragment(&active_key);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "deletion target is not a regular file or directory",
            ));
        };
        if let Err(error) = parent.directory.sync_all() {
            tracing::warn!(%error, "staged deletion but source-directory sync was uncertain");
        }
        if let Err(error) = self.tombstones.sync_all() {
            tracing::warn!(%error, "staged deletion but tombstone-directory sync was uncertain");
        }
        Ok(StagedDelete {
            original_path,
            tombstone_path: tombstone_name.clone(),
            status,
            committed: false,
            parent: rollback_parent,
            staging: transaction_staging,
            original_name,
            tombstone_name,
            manifest_name,
            active_key: Some(active_key),
            #[cfg(test)]
            next_promotion_rename_error: self.next_delete_promotion_rename_error.clone(),
        })
    }

    #[cfg(test)]
    fn fail_next_delete_staging_rename_after_success(&self, kind: io::ErrorKind) {
        *self
            .next_delete_staging_rename_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }

    #[cfg(test)]
    fn fail_next_delete_promotion_rename_after_success(&self, kind: io::ErrorKind) {
        *self
            .next_delete_promotion_rename_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(kind);
    }

    pub fn begin_upload(&self, directory: &str) -> io::Result<PendingUpload> {
        self.root.begin_upload(directory)
    }

    /// Starts a recursive cleanup cursor suitable for bounded background batches.
    /// Uploads active in this process are registered and cannot be removed by it.
    pub fn start_upload_fragment_cleanup(&self) -> io::Result<UploadFragmentCleanup> {
        use std::os::unix::fs::MetadataExt;

        let uploads = self.root.staging.as_ref().try_clone()?;
        let tombstones = self.tombstones.as_ref().try_clone()?;
        let upload_identity = uploads.metadata()?;
        let tombstone_identity = tombstones.metadata()?;
        Ok(UploadFragmentCleanup {
            directories: vec![
                cleanup_directory_from_file(tombstones, CleanupPolicy::TombstoneRoot)?,
                cleanup_directory_from_file(uploads, CleanupPolicy::UploadFragments)?,
            ],
            visited: HashSet::from([
                (upload_identity.dev(), upload_identity.ino()),
                (tombstone_identity.dev(), tombstone_identity.ino()),
            ]),
        })
    }

    pub fn start_deletion_cleanup(
        &self,
        tombstone_relative: &str,
    ) -> io::Result<UploadFragmentCleanup> {
        let (parent_path, tombstone_name) = split_parent_name_private(tombstone_relative)?;
        if !parent_path.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "deletion tombstone must be inside the private tombstone staging directory",
            ));
        }
        if !is_deletion_tombstone_name(OsStr::new(&tombstone_name)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid deletion tombstone",
            ));
        }
        use std::os::unix::fs::MetadataExt;
        let directory = linux::openat2(
            self.tombstones.as_ref(),
            &tombstone_name,
            linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
        )?;
        let metadata = directory.metadata()?;
        let mut cleanup = cleanup_directory_from_file(directory, CleanupPolicy::DeleteAll)?;
        cleanup.remove_from = Some((
            self.tombstones.as_ref().try_clone()?,
            OsString::from(tombstone_name),
        ));
        Ok(UploadFragmentCleanup {
            directories: vec![cleanup],
            visited: HashSet::from([(metadata.dev(), metadata.ino())]),
        })
    }
}

impl SecureDirectory {
    fn open_user_path(&self, path: impl AsRef<Path>, flags: linux::OpenFlags) -> io::Result<File> {
        linux::openat2_scoped(self.directory.as_ref(), path, flags, self.forbid_symlinks)
    }

    /// Narrows this capability to a child directory. The final component must not be a symlink.
    pub fn bind_directory(&self, relative: &str) -> io::Result<Self> {
        let relative = validated(relative)?;
        Ok(Self {
            directory: Arc::new(self.open_user_path(
                &relative,
                linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
            )?),
            staging: self.staging.clone(),
            forbid_symlinks: self.forbid_symlinks,
            allow_replace: self.allow_replace,
        })
    }

    fn entry_status(&self, name: &str) -> io::Result<EntryStatus> {
        path_security::safe_admin_filename(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid entry name"))?;
        let child = self.open_user_path(name, linux::O_PATH | linux::O_NOFOLLOW)?;
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
            let directory = self.open_user_path(
                name,
                linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
            )?;
            directory_scan_from_file(directory, self.forbid_symlinks)?
                .entries
                .next()
                .is_some()
        } else {
            false
        };
        Ok(EntryStatus {
            kind,
            directory_non_empty,
        })
    }

    fn create_directory(&self, name: &str) -> io::Result<()> {
        path_security::safe_admin_filename(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid directory name"))?;
        linux::mkdir(self.directory.as_ref(), name)?;
        if let Err(error) = self.directory.sync_all() {
            tracing::warn!(%error, "created directory but parent sync was uncertain");
        }
        Ok(())
    }

    fn rename_noreplace(&self, old: &str, new: &str) -> io::Result<()> {
        linux::rename_noreplace(self.directory.as_ref(), old, new)?;
        if let Err(error) = self.directory.sync_all() {
            tracing::warn!(%error, "renamed entry but parent sync was uncertain");
        }
        Ok(())
    }

    pub fn open_file(&self, relative: &str) -> io::Result<SecureFile> {
        let relative = validated(relative)?;
        let probe = self.open_user_path(&relative, linux::O_PATH | linux::O_NOFOLLOW)?;
        if !probe.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "target is not a regular file",
            ));
        }
        let file = self.open_user_path(
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

    pub fn metadata(&self, relative: &str) -> io::Result<std::fs::Metadata> {
        let relative = validated(relative)?;
        self.open_user_path(&relative, linux::O_PATH | linux::O_NOFOLLOW)?
            .metadata()
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
        let directory = self.open_user_path(
            &relative,
            linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
        )?;
        directory_scan_from_file(directory, self.forbid_symlinks)
    }

    pub fn begin_upload(&self, directory: &str) -> io::Result<PendingUpload> {
        let directory = validated(directory)?;
        let destination = self.open_user_path(
            &directory,
            linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
        )?;
        PendingUpload::new(
            self.staging.as_ref().try_clone()?,
            destination,
            self.allow_replace,
        )
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
        start_cleanup_from_directory(self.staging.as_ref(), CleanupPolicy::UploadFragments)
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

fn directory_scan_from_file(
    directory: File,
    strict_mount_boundary: bool,
) -> io::Result<DirectoryScan> {
    use std::os::fd::AsRawFd;

    let proc_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let entries = std::fs::read_dir(proc_path)?;
    Ok(DirectoryScan {
        entries,
        directory,
        strict_mount_boundary,
    })
}

fn cleanup_directory_from_file(
    directory: File,
    policy: CleanupPolicy,
) -> io::Result<CleanupDirectory> {
    use std::os::fd::AsRawFd;

    let proc_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let entries = std::fs::read_dir(proc_path)?;
    Ok(CleanupDirectory {
        directory,
        entries,
        removed_in_pass: false,
        policy,
        remove_from: None,
    })
}

fn start_cleanup_from_directory(
    root: &File,
    policy: CleanupPolicy,
) -> io::Result<UploadFragmentCleanup> {
    use std::os::unix::fs::MetadataExt;

    let root = root.try_clone()?;
    let metadata = root.metadata()?;
    let directory = cleanup_directory_from_file(root, policy)?;
    Ok(UploadFragmentCleanup {
        directories: vec![directory],
        visited: HashSet::from([(metadata.dev(), metadata.ino())]),
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
        linux::rename_noreplace(&self.parent, &self.new_name, &self.original_name)?;
        if let Err(error) = self.parent.sync_all() {
            tracing::warn!(%error, "rolled back rename but parent sync was uncertain");
        }
        Ok(())
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
        // Only a committed name is eligible for restart cleanup. The database
        // change has already succeeded before this method is called.
        let committed_tombstone = self.promote_for_cleanup()?;
        if let Err(error) = self.staging.sync_all() {
            tracing::warn!(%error, "committed deletion tombstone but staging sync was uncertain");
        }
        self.committed = true;
        self.release_active();
        if self.status.kind == EntryKind::Directory && self.status.directory_non_empty {
            return Ok(DeleteCommitOutcome {
                cleanup_pending: true,
                tombstone_path: Some(committed_tombstone),
            });
        }
        let removal = match self.status.kind {
            EntryKind::File => linux::unlink(&self.staging, OsStr::new(&self.tombstone_name)),
            EntryKind::Directory => linux::rmdir(&self.staging, OsStr::new(&self.tombstone_name)),
        };
        if let Err(error) = removal {
            tracing::warn!(%error, tombstone = %self.tombstone_path, "deletion tombstone cleanup deferred");
            return Ok(DeleteCommitOutcome {
                cleanup_pending: true,
                tombstone_path: Some(committed_tombstone),
            });
        }
        if let Err(error) = self.staging.sync_all() {
            tracing::warn!(%error, "removed deletion tombstone but staging sync was uncertain");
        }
        Ok(DeleteCommitOutcome {
            cleanup_pending: false,
            tombstone_path: None,
        })
    }

    fn rollback(&self) -> io::Result<()> {
        linux::rename_noreplace_between(
            &self.staging,
            &self.tombstone_name,
            &self.parent,
            &self.original_name,
        )?;
        self.staging.sync_all()?;
        self.parent.sync_all()?;
        if let Err(error) = remove_pending_manifest(&self.staging, &self.manifest_name) {
            tracing::warn!(%error, manifest = %self.manifest_name, "could not remove durable rollback manifest");
        }
        Ok(())
    }

    fn promote_for_cleanup(&mut self) -> io::Result<String> {
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
            let rename =
                linux::rename_noreplace(&self.staging, &self.tombstone_name, &committed_name);
            #[cfg(test)]
            let rename = inject_error_after_successful_rename(
                rename,
                self.next_promotion_rename_error.as_ref(),
            );
            match rename {
                Ok(()) => {
                    return Ok(self.finish_promotion(committed_name));
                }
                Err(error) => {
                    if entry_matches_identity(
                        &self.staging,
                        &committed_name,
                        pending_identity,
                        self.status.kind,
                    ) {
                        tracing::warn!(%error, tombstone = %committed_name, "committed deletion rename returned an error after the pending entry moved; continuing with verified identity");
                        return Ok(self.finish_promotion(committed_name));
                    }
                    unregister_upload_fragment(&committed_name);
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
        match self.staging.sync_all() {
            Ok(()) => {
                if let Err(error) = remove_pending_manifest(&self.staging, &self.manifest_name) {
                    tracing::warn!(%error, manifest = %self.manifest_name, "could not remove committed deletion manifest");
                }
            }
            Err(error) => {
                tracing::warn!(%error, manifest = %self.manifest_name, "committed deletion rename sync was uncertain; recovery manifest was retained");
            }
        }
        committed_name
    }

    fn release_active(&mut self) {
        if let Some(active_key) = self.active_key.take() {
            unregister_upload_fragment(&active_key);
        }
    }
}

#[cfg(test)]
fn inject_error_after_successful_rename(
    rename: io::Result<()>,
    next_error: &Mutex<Option<io::ErrorKind>>,
) -> io::Result<()> {
    rename?;
    let kind = next_error
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    match kind {
        Some(kind) => Err(io::Error::new(kind, "injected rename response loss")),
        None => Ok(()),
    }
}

impl Drop for StagedDelete {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(error) = self.rollback() {
                // Pending names are deliberately excluded from every automatic
                // cleanup pass. If a co-writer occupied the original name, both
                // objects survive and an operator can recover the pending entry.
                tracing::error!(%error, recovery_entry = %self.tombstone_path, original = %self.original_path, "could not roll back staged deletion; private recovery entry was preserved");
            }
        }
        self.release_active();
    }
}

pub struct PendingUpload {
    staging: File,
    destination: File,
    temporary_name: String,
    file: Option<File>,
    active_key: Option<ActiveUploadFragmentKey>,
    expected_identity: (u64, u64),
    allow_replace: bool,
    published: bool,
    #[cfg(test)]
    next_directory_sync_error: Option<io::ErrorKind>,
}

impl PendingUpload {
    fn new(staging: File, destination: File, allow_replace: bool) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        if staging.metadata()?.dev() != destination.metadata()?.dev() {
            return Err(io::Error::new(
                io::ErrorKind::CrossesDevices,
                "upload staging and destination must be on the same filesystem",
            ));
        }
        for _ in 0..16 {
            let temporary_name = upload_fragment_name();
            if !active_upload_fragment_guard().insert(temporary_name.clone()) {
                continue;
            }
            match linux::openat2(
                &staging,
                &temporary_name,
                linux::O_WRONLY | linux::O_CREAT | linux::O_EXCL,
            ) {
                Ok(file) => {
                    let metadata = match file.metadata() {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            drop(file);
                            let _ = linux::unlink(&staging, &temporary_name);
                            unregister_upload_fragment(&temporary_name);
                            return Err(error);
                        }
                    };
                    let expected_identity = (metadata.dev(), metadata.ino());
                    let active_key = temporary_name.clone();
                    return Ok(Self {
                        staging,
                        destination,
                        temporary_name,
                        file: Some(file),
                        active_key: Some(active_key),
                        expected_identity,
                        allow_replace,
                        published: false,
                        #[cfg(test)]
                        next_directory_sync_error: None,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    unregister_upload_fragment(&temporary_name);
                    continue;
                }
                Err(error) => {
                    unregister_upload_fragment(&temporary_name);
                    return Err(error);
                }
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
        self.validate_staging_identity()?;
        let rename = linux::rename_noreplace_between(
            &self.staging,
            &self.temporary_name,
            &self.destination,
            name,
        );
        if let Err(error) = rename {
            if entry_matches_identity(
                &self.destination,
                name,
                self.expected_identity,
                EntryKind::File,
            ) {
                tracing::warn!(%error, destination = %name, "upload rename returned an error after publication; continuing with verified identity");
            } else {
                return Err(error);
            }
        }
        Ok(self.finish_publication())
    }

    pub fn publish_replace(&mut self, name: &str) -> io::Result<PublishOutcome> {
        if !self.allow_replace {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "replacement publication is disabled for external-writer storage",
            ));
        }
        let name = upload_destination_name(name)?;
        self.validate_staging_identity()?;
        let rename = linux::rename_replace_between(
            &self.staging,
            &self.temporary_name,
            &self.destination,
            name,
        );
        if let Err(error) = rename {
            if entry_matches_identity(
                &self.destination,
                name,
                self.expected_identity,
                EntryKind::File,
            ) {
                tracing::warn!(%error, destination = %name, "replacement rename returned an error after publication; continuing with verified identity");
            } else {
                return Err(error);
            }
        }
        Ok(self.finish_publication())
    }

    fn validate_staging_identity(&self) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        if self.active_key.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "upload is no longer active",
            ));
        }
        let expected = self.expected_identity;
        let current = linux::openat2(
            &self.staging,
            &self.temporary_name,
            linux::O_PATH | linux::O_NOFOLLOW,
        )?;
        let metadata = current.metadata()?;
        if !metadata.is_file() || (metadata.dev(), metadata.ino()) != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "upload staging entry changed before atomic publication",
            ));
        }
        Ok(())
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
        self.destination.sync_all()?;
        self.staging.sync_all()
    }

    #[cfg(test)]
    pub(crate) fn fail_next_directory_sync(&mut self, kind: io::ErrorKind) {
        self.next_directory_sync_error = Some(kind);
    }
}

impl Drop for PendingUpload {
    fn drop(&mut self) {
        if !self.published {
            let _ = linux::unlink(&self.staging, &self.temporary_name);
        }
        if let Some(active_key) = self.active_key.take() {
            unregister_upload_fragment(&active_key);
        }
    }
}

mod linux {
    use std::{fs::File, io, path::Path};

    use rustix::fs::{
        mkdirat, openat2 as rustix_openat2, renameat, renameat_with, unlinkat, AtFlags, Mode,
        OFlags, RenameFlags, ResolveFlags,
    };

    pub type OpenFlags = OFlags;

    pub const O_RDONLY: OFlags = OFlags::RDONLY;
    pub const O_WRONLY: OFlags = OFlags::WRONLY;
    pub const O_CREAT: OFlags = OFlags::CREATE;
    pub const O_EXCL: OFlags = OFlags::EXCL;
    pub const O_NONBLOCK: OFlags = OFlags::NONBLOCK;
    pub const O_NOFOLLOW: OFlags = OFlags::NOFOLLOW;
    pub const O_DIRECTORY: OFlags = OFlags::DIRECTORY;
    pub const O_PATH: OFlags = OFlags::PATH;

    fn std_error(error: rustix::io::Errno) -> io::Error {
        io::Error::from_raw_os_error(error.raw_os_error())
    }

    pub fn openat2(directory: &File, path: impl AsRef<Path>, flags: OFlags) -> io::Result<File> {
        openat2_scoped(directory, path, flags, false)
    }

    pub fn openat2_scoped(
        directory: &File,
        path: impl AsRef<Path>,
        flags: OFlags,
        forbid_symlinks: bool,
    ) -> io::Result<File> {
        let mode = if flags.contains(OFlags::CREATE) {
            Mode::from_raw_mode(0o600)
        } else {
            Mode::empty()
        };
        let mut resolve = ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS;
        if forbid_symlinks {
            resolve |= ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV;
        }
        rustix_openat2(
            directory,
            path.as_ref(),
            flags | OFlags::CLOEXEC,
            mode,
            resolve,
        )
        .map(File::from)
        .map_err(std_error)
    }

    pub fn rename_noreplace(directory: &File, old: &str, new: &str) -> io::Result<()> {
        rename_noreplace_between(directory, old, directory, new)
    }

    pub fn rename_noreplace_between(
        old_directory: &File,
        old: &str,
        new_directory: &File,
        new: &str,
    ) -> io::Result<()> {
        renameat_with(
            old_directory,
            old,
            new_directory,
            new,
            RenameFlags::NOREPLACE,
        )
        .map_err(std_error)
    }

    pub fn rename_replace_between(
        old_directory: &File,
        old: &str,
        new_directory: &File,
        new: &str,
    ) -> io::Result<()> {
        renameat(old_directory, old, new_directory, new).map_err(std_error)
    }

    pub fn unlink(directory: &File, name: impl AsRef<Path>) -> io::Result<()> {
        unlinkat(directory, name.as_ref(), AtFlags::empty()).map_err(std_error)
    }

    pub fn rmdir(directory: &File, name: impl AsRef<Path>) -> io::Result<()> {
        unlinkat(directory, name.as_ref(), AtFlags::REMOVEDIR).map_err(std_error)
    }

    pub fn mkdir(directory: &File, name: impl AsRef<Path>) -> io::Result<()> {
        mkdirat(directory, name.as_ref(), Mode::from_raw_mode(0o700)).map_err(std_error)
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
        assert!(root.list("", 0, 10).unwrap().is_empty());
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

        assert_eq!(root.cleanup_upload_fragments(100).unwrap(), 1);
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

            let outcome = staged.commit().unwrap();
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
        assert_eq!(root.cleanup_upload_fragments(100).unwrap(), 0);
        assert_eq!(std::fs::read(recovery_path).unwrap(), b"original");
        drop(root);
        let reopened = SecureRoot::open(directory.path()).unwrap();
        assert_eq!(
            std::fs::read(directory.path().join("report.txt")).unwrap(),
            b"external"
        );
        assert!(manifest_path.is_file());
        drop(reopened);
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
    fn committed_delete_removes_pending_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("delete.txt"), b"content").unwrap();
        let staged = root.stage_delete("delete.txt").unwrap();
        assert!(staged.commit().unwrap().tombstone_path.is_none());
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
