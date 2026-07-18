use std::{ffi::OsString, fs::File, io, path::Path, sync::Arc};

use crate::path_security;

use super::private_entries::is_upload_fragment_name;
use super::{
    is_deletion_tombstone_name, split_parent_name, validated, DirectoryScan, DirectoryScanBatch,
    DirectoryScanItem, Entry, EntryKind, EntryStatus, SecureDirectory, SecureFile, SecureRoot,
};

impl DirectoryScanItem {
    pub fn into_entry(self) -> Option<Entry> {
        match self {
            Self::Visible(entry) => Some(entry),
            Self::Filtered => None,
        }
    }
}

fn visible_entry(name: &OsString, metadata: &std::fs::Metadata) -> DirectoryScanItem {
    if path_security::is_internal_storage_name(name)
        || is_upload_fragment_name(name)
        || is_deletion_tombstone_name(name)
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
        Some(visible_entry(&name, &metadata))
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

impl SecureRoot {
    pub(crate) fn readiness_check(&self) -> io::Result<()> {
        for (name, directory) in [
            ("root", self.root.directory.as_ref()),
            ("uploads", self.root.staging.as_ref()),
            ("tombstones", self.tombstones.as_ref()),
        ] {
            if !directory.metadata()?.is_dir() {
                return Err(io::Error::other(format!(
                    "{name} capability is no longer a directory"
                )));
            }
            let filesystem = rustix::fs::fstatvfs(directory)?;
            if filesystem
                .f_flag
                .contains(rustix::fs::StatVfsMountFlags::RDONLY)
            {
                return Err(io::Error::other(format!("{name} filesystem is read-only")));
            }
            if filesystem.f_bavail == 0 {
                return Err(io::Error::other(format!(
                    "{name} filesystem has no available blocks"
                )));
            }
        }
        Ok(())
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
}

impl SecureDirectory {
    pub(super) fn open_user_path(
        &self,
        path: impl AsRef<Path>,
        flags: linux::OpenFlags,
    ) -> io::Result<File> {
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
            _storage_instance_lock: self._storage_instance_lock.clone(),
            #[cfg(test)]
            next_create_directory_sync_error: self.next_create_directory_sync_error.clone(),
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
}

impl SecureFile {
    pub fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.file.metadata()
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

pub(super) fn directory_scan_from_file(
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

pub(super) mod linux {
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
        old: impl AsRef<Path>,
        new_directory: &File,
        new: impl AsRef<Path>,
    ) -> io::Result<()> {
        renameat_with(
            old_directory,
            old.as_ref(),
            new_directory,
            new.as_ref(),
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
