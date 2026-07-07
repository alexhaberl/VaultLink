//! Descriptor-relative storage access. Linux production builds use `openat2(2)`
//! so a path cannot escape the configured root between validation and use.

use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

#[cfg(target_os = "linux")]
use std::sync::Arc;

use crate::path_security;

#[derive(Clone)]
pub struct SecureRoot {
    display_root: PathBuf,
    #[cfg(target_os = "linux")]
    root: Arc<File>,
}

#[derive(Debug)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub len: u64,
    pub modified: Option<SystemTime>,
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
            let root = Arc::new(File::open(&display_root)?);
            // Probe the required kernel API at startup and fail with a useful error.
            linux::openat2(root.as_ref(), ".", linux::O_RDONLY | linux::O_DIRECTORY)?;
            Ok(Self { display_root, root })
        }
        #[cfg(not(target_os = "linux"))]
        Ok(Self { display_root })
    }

    pub fn display_root(&self) -> &Path {
        &self.display_root
    }

    pub fn open_file(&self, relative: &str) -> io::Result<File> {
        let relative = validated(relative)?;
        #[cfg(target_os = "linux")]
        return linux::openat2(
            self.root.as_ref(),
            &relative,
            linux::O_RDONLY | linux::O_NOFOLLOW,
        );
        #[cfg(not(target_os = "linux"))]
        return File::open(
            path_security::resolve_existing(&self.display_root, &relative).map_err(path_error)?,
        );
    }

    pub fn metadata(&self, relative: &str) -> io::Result<std::fs::Metadata> {
        let relative = validated(relative)?;
        #[cfg(target_os = "linux")]
        return linux::openat2(
            self.root.as_ref(),
            &relative,
            linux::O_PATH | linux::O_NOFOLLOW,
        )?
        .metadata();
        #[cfg(not(target_os = "linux"))]
        return std::fs::metadata(
            path_security::resolve_existing(&self.display_root, &relative).map_err(path_error)?,
        );
    }

    pub fn list(&self, relative: &str, offset: usize, limit: usize) -> io::Result<Vec<Entry>> {
        let relative = validated(relative)?;
        #[cfg(target_os = "linux")]
        {
            let directory = linux::openat2(
                self.root.as_ref(),
                &relative,
                linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
            )?;
            linux::list(&directory, offset, limit)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let directory = path_security::resolve_existing(&self.display_root, &relative)
                .map_err(path_error)?;
            std::fs::read_dir(directory)?
                .skip(offset)
                .take(limit)
                .filter_map(|item| {
                    let item = item.ok()?;
                    let metadata = item.metadata().ok()?;
                    Some(Ok(Entry {
                        name: item.file_name().to_string_lossy().into_owned(),
                        is_dir: metadata.is_dir(),
                        len: metadata.len(),
                        modified: metadata.modified().ok(),
                    }))
                })
                .collect()
        }
    }

    pub fn begin_upload(&self, directory: &str) -> io::Result<PendingUpload> {
        let directory = validated(directory)?;
        #[cfg(target_os = "linux")]
        {
            let dir = linux::openat2(
                self.root.as_ref(),
                &directory,
                linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
            )?;
            PendingUpload::new(dir)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let dir = path_security::resolve_existing(&self.display_root, &directory)
                .map_err(path_error)?;
            PendingUpload::new(dir)
        }
    }
}

fn validated(raw: &str) -> io::Result<String> {
    let path = path_security::validate_relative(raw).map_err(path_error)?;
    let value = path.to_string_lossy().replace('\\', "/");
    Ok(if value.is_empty() { ".".into() } else { value })
}

fn path_error(error: path_security::PathError) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, error.to_string())
}

#[cfg(target_os = "linux")]
pub struct PendingUpload {
    directory: File,
    temporary_name: String,
    file: Option<File>,
    published: bool,
}

#[cfg(target_os = "linux")]
impl PendingUpload {
    fn new(directory: File) -> io::Result<Self> {
        for _ in 0..16 {
            let temporary_name = format!(".vaultlink-{}.part", crate::auth::random_token(18));
            match linux::openat2(
                &directory,
                &temporary_name,
                linux::O_WRONLY | linux::O_CREAT | linux::O_EXCL,
            ) {
                Ok(file) => {
                    return Ok(Self {
                        directory,
                        temporary_name,
                        file: Some(file),
                        published: false,
                    })
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
    pub fn take_file(&mut self) -> File {
        self.file.take().expect("upload file already taken")
    }
    pub fn publish(&mut self, name: &str) -> io::Result<()> {
        linux::rename_noreplace(&self.directory, &self.temporary_name, name)?;
        self.directory.sync_all()?;
        self.published = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for PendingUpload {
    fn drop(&mut self) {
        if !self.published {
            let _ = linux::unlink(&self.directory, &self.temporary_name);
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub struct PendingUpload {
    temporary: Option<tempfile::NamedTempFile>,
    directory: PathBuf,
}

#[cfg(not(target_os = "linux"))]
impl PendingUpload {
    fn new(directory: PathBuf) -> io::Result<Self> {
        Ok(Self {
            temporary: Some(tempfile::NamedTempFile::new_in(&directory)?),
            directory,
        })
    }
    pub fn take_file(&mut self) -> File {
        self.temporary
            .as_ref()
            .expect("upload file already taken")
            .reopen()
            .expect("reopen temporary upload")
    }
    pub fn publish(&mut self, name: &str) -> io::Result<()> {
        let temporary = self.temporary.take().expect("upload already published");
        temporary
            .persist_noclobber(self.directory.join(name))
            .map(|_| ())
            .map_err(|error| error.error)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::Entry;
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
    pub const O_NOFOLLOW: u64 = 0o400000;
    pub const O_DIRECTORY: u64 = 0o200000;
    pub const O_PATH: u64 = 0o10000000;
    const O_CLOEXEC: u64 = 0o2000000;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_BENEATH: u64 = 0x08;
    const RENAME_NOREPLACE: c_uint = 1;

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
    }

    #[cfg(target_arch = "x86_64")]
    const SYS_OPENAT2: c_long = 437;
    #[cfg(not(target_arch = "x86_64"))]
    compile_error!("VaultLink v0.1.0-beta.1 Linux release supports amd64 only");

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

    pub fn list(directory: &File, offset: usize, limit: usize) -> io::Result<Vec<Entry>> {
        let proc_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
        std::fs::read_dir(proc_path)?
            .skip(offset)
            .filter_map(|item| {
                let item = item.ok()?;
                let name = item.file_name();
                let child = openat2(directory, &name, O_PATH | O_NOFOLLOW).ok()?;
                let metadata = child.metadata().ok()?;
                Some(Entry {
                    name: name.to_string_lossy().into_owned(),
                    is_dir: metadata.is_dir(),
                    len: metadata.len(),
                    modified: metadata.modified().ok(),
                })
            })
            .take(limit)
            .map(Ok)
            .collect()
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

    pub fn unlink(directory: &File, name: &str) -> io::Result<()> {
        let name = c_path(name)?;
        // SAFETY: C string and descriptor are valid; flags=0 removes files only.
        let result = unsafe { unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
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
    fn upload_publish_is_noclobber_and_cleans_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        std::fs::write(directory.path().join("existing.txt"), b"original").unwrap();

        let mut upload = root.begin_upload("").unwrap();
        let mut file = upload.take_file();
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
        let mut file = upload.take_file();
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
    fn abandoned_upload_is_removed() {
        let directory = tempfile::tempdir().unwrap();
        let root = SecureRoot::open(directory.path()).unwrap();
        {
            let mut upload = root.begin_upload("").unwrap();
            let mut file = upload.take_file();
            file.write_all(b"partial").unwrap();
        }
        let names: Vec<_> = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(names.is_empty(), "temporary upload remained: {names:?}");
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
                    let mut file = upload.take_file();
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
}
