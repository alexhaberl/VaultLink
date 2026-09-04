//! Descriptor-based loading for operator-provided TLS certificate files.
//!
//! Paths are resolved one component at a time below already validated directory
//! descriptors. Regular symlinks are supported for atomic certificate rotation,
//! while procfs magic links and path re-resolution after validation are rejected.

use std::{
    collections::VecDeque,
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read},
    os::unix::ffi::OsStringExt,
    path::{Component, Path, PathBuf},
};

use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, Stat};

const MAX_CERTIFICATE_CHAIN_BYTES: u64 = 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 128 * 1024;
const MAX_SYMLINKS: usize = 40;
const MAX_PATH_COMPONENTS: usize = 256;

fn normalized_link_count<T: Into<u64>>(links: T) -> u64 {
    links.into()
}

/// PEM data read only from descriptors whose paths and metadata were validated.
pub struct ValidatedTlsPem {
    pub certificate_chain: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Clone, Copy)]
enum TlsFileKind {
    CertificateChain,
    PrivateKey,
}

impl TlsFileKind {
    fn label(self) -> &'static str {
        match self {
            Self::CertificateChain => "certificate chain",
            Self::PrivateKey => "private key",
        }
    }

    fn maximum_size(self) -> u64 {
        match self {
            Self::CertificateChain => MAX_CERTIFICATE_CHAIN_BYTES,
            Self::PrivateKey => MAX_PRIVATE_KEY_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetadataSnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    links: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

impl MetadataSnapshot {
    fn from_stat(stat: &Stat, kind: TlsFileKind, service_uid: u32) -> io::Result<Self> {
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(invalid(kind, "must be a regular file"));
        }
        validate_owner(stat.st_uid, service_uid, kind)?;
        validate_file_mode(stat.st_mode & 0o7777, kind)?;
        if matches!(kind, TlsFileKind::PrivateKey) && stat.st_nlink != 1 {
            return Err(invalid(kind, "must have exactly one hard link"));
        }
        let size = u64::try_from(stat.st_size)
            .map_err(|_| invalid(kind, "has an invalid negative size"))?;
        if size == 0 {
            return Err(invalid(kind, "must not be empty"));
        }
        if size > kind.maximum_size() {
            return Err(invalid(kind, "exceeds the maximum allowed size"));
        }
        Ok(Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            owner: stat.st_uid,
            links: normalized_link_count(stat.st_nlink),
            size,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        })
    }
}

struct ValidatedFile {
    file: File,
    metadata: MetadataSnapshot,
    kind: TlsFileKind,
}

impl ValidatedFile {
    fn read(mut self, service_uid: u32) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.metadata.size as usize);
        (&mut self.file)
            .take(self.kind.maximum_size() + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > self.kind.maximum_size() {
            return Err(invalid(self.kind, "grew beyond the maximum allowed size"));
        }
        let after = rustix::fs::fstat(&self.file).map_err(std_error)?;
        let after = MetadataSnapshot::from_stat(&after, self.kind, service_uid)?;
        if after != self.metadata || bytes.len() as u64 != self.metadata.size {
            return Err(invalid(self.kind, "changed while it was being read"));
        }
        Ok(bytes)
    }
}

#[derive(Debug)]
enum PathStep {
    Root,
    Parent,
    Name(OsString),
}

/// Validate both configured paths without parsing their PEM contents.
pub fn validate_tls_file_paths(cert_file: &Path, key_file: &Path) -> io::Result<()> {
    let service_uid = rustix::process::geteuid().as_raw();
    open_validated_file(cert_file, TlsFileKind::CertificateChain, service_uid)?;
    open_validated_file(key_file, TlsFileKind::PrivateKey, service_uid)?;
    Ok(())
}

/// Open and read both TLS inputs from their validated descriptors.
pub fn read_validated_tls_pem(cert_file: &Path, key_file: &Path) -> io::Result<ValidatedTlsPem> {
    let service_uid = rustix::process::geteuid().as_raw();
    // Anchor both names before reading either file so an atomic rotation cannot
    // redirect a descriptor after its metadata was accepted.
    let certificate = open_validated_file(cert_file, TlsFileKind::CertificateChain, service_uid)?;
    let private_key = open_validated_file(key_file, TlsFileKind::PrivateKey, service_uid)?;
    Ok(ValidatedTlsPem {
        certificate_chain: certificate.read(service_uid)?,
        private_key: private_key.read(service_uid)?,
    })
}

fn open_validated_file(
    path: &Path,
    kind: TlsFileKind,
    service_uid: u32,
) -> io::Result<ValidatedFile> {
    open_validated_file_with_hook(path, kind, service_uid, &mut || {})
}

fn open_validated_file_with_hook(
    path: &Path,
    kind: TlsFileKind,
    service_uid: u32,
    before_final_open: &mut dyn FnMut(),
) -> io::Result<ValidatedFile> {
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let root = File::open("/")?;
    validate_directory(&rustix::fs::fstat(&root).map_err(std_error)?, service_uid)?;
    let mut directories = vec![root];
    let mut pending = path_steps(&absolute_path)?;
    let mut symlinks = 0_usize;
    let mut processed_components = 0_usize;

    while let Some(step) = pending.pop_front() {
        match step {
            PathStep::Root => directories.truncate(1),
            PathStep::Parent => {
                if directories.len() > 1 {
                    directories.pop();
                }
            }
            PathStep::Name(name) => {
                processed_components += 1;
                if processed_components > MAX_PATH_COMPONENTS {
                    return Err(invalid(kind, "contains too many path components"));
                }
                let parent = directories
                    .last()
                    .expect("the filesystem root descriptor is retained");
                let entry = open_path_entry(parent, &name).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("cannot securely inspect TLS {}: {error}", kind.label()),
                    )
                })?;
                let stat = rustix::fs::fstat(&entry).map_err(std_error)?;
                validate_owner(stat.st_uid, service_uid, kind)?;
                match FileType::from_raw_mode(stat.st_mode) {
                    FileType::Symlink => {
                        symlinks += 1;
                        if symlinks > MAX_SYMLINKS {
                            return Err(invalid(kind, "contains too many symbolic links"));
                        }
                        if rustix::fs::fstatfs(&entry).map_err(std_error)?.f_type
                            == rustix::fs::PROC_SUPER_MAGIC
                        {
                            return Err(invalid(kind, "must not traverse a magic link"));
                        }
                        let target =
                            rustix::fs::readlinkat(&entry, "", Vec::new()).map_err(std_error)?;
                        let target = PathBuf::from(OsString::from_vec(target.into_bytes()));
                        prepend_path_steps(&target, &mut pending)?;
                    }
                    FileType::Directory => {
                        validate_directory(&stat, service_uid)?;
                        directories.push(entry);
                    }
                    FileType::RegularFile if pending.is_empty() => {
                        let inspected = MetadataSnapshot::from_stat(&stat, kind, service_uid)?;
                        before_final_open();
                        let opened = open_regular_file(parent, &name).map_err(|error| {
                            io::Error::new(
                                error.kind(),
                                format!("cannot securely open TLS {}: {error}", kind.label()),
                            )
                        })?;
                        let opened_stat = rustix::fs::fstat(&opened).map_err(std_error)?;
                        let opened_metadata =
                            MetadataSnapshot::from_stat(&opened_stat, kind, service_uid)?;
                        if opened_metadata != inspected {
                            return Err(invalid(kind, "changed while it was being opened"));
                        }
                        return Ok(ValidatedFile {
                            file: opened,
                            metadata: opened_metadata,
                            kind,
                        });
                    }
                    FileType::RegularFile => {
                        return Err(invalid(kind, "has a non-directory path component"));
                    }
                    _ => return Err(invalid(kind, "must resolve to a regular file")),
                }
            }
        }
    }
    Err(invalid(kind, "does not name a regular file"))
}

fn open_path_entry(parent: &File, name: &OsStr) -> io::Result<File> {
    openat2_component(parent, name, OFlags::PATH | OFlags::NOFOLLOW)
}

fn open_regular_file(parent: &File, name: &OsStr) -> io::Result<File> {
    openat2_component(parent, name, OFlags::RDONLY | OFlags::NOFOLLOW)
}

fn openat2_component(parent: &File, name: &OsStr, flags: OFlags) -> io::Result<File> {
    rustix::fs::openat2(
        parent,
        Path::new(name),
        flags | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map(File::from)
    .map_err(std_error)
}

fn path_steps(path: &Path) -> io::Result<VecDeque<PathStep>> {
    let mut steps = VecDeque::new();
    for component in path.components() {
        match component {
            Component::RootDir => steps.push_back(PathStep::Root),
            Component::CurDir => {}
            Component::ParentDir => steps.push_back(PathStep::Parent),
            Component::Normal(name) => steps.push_back(PathStep::Name(name.to_os_string())),
            Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TLS paths must use Linux path syntax",
                ));
            }
        }
    }
    Ok(steps)
}

fn prepend_path_steps(target: &Path, pending: &mut VecDeque<PathStep>) -> io::Result<()> {
    let mut target_steps = path_steps(target)?;
    target_steps.append(pending);
    *pending = target_steps;
    Ok(())
}

fn validate_directory(stat: &Stat, service_uid: u32) -> io::Result<()> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS path parent must be a directory",
        ));
    }
    validate_owner_raw(stat.st_uid, service_uid, "TLS path parent")?;
    let mode = stat.st_mode & 0o7777;
    let writable_by_group_or_other = mode & 0o022 != 0;
    let protected_temporary_directory = stat.st_uid == 0 && mode & 0o1000 != 0;
    if writable_by_group_or_other && !protected_temporary_directory {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "TLS path parent must not be group- or world-writable",
        ));
    }
    Ok(())
}

fn validate_owner(owner: u32, service_uid: u32, kind: TlsFileKind) -> io::Result<()> {
    validate_owner_raw(owner, service_uid, &format!("TLS {}", kind.label()))
}

fn validate_owner_raw(owner: u32, service_uid: u32, label: &str) -> io::Result<()> {
    if owner != 0 && owner != service_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{label} must be owned by root or the service user"),
        ));
    }
    Ok(())
}

fn validate_file_mode(mode: u32, kind: TlsFileKind) -> io::Result<()> {
    match kind {
        TlsFileKind::PrivateKey if !matches!(mode, 0o400 | 0o440 | 0o600 | 0o640) => {
            Err(invalid(kind, "mode must be 0400, 0440, 0600, or 0640"))
        }
        TlsFileKind::CertificateChain
            if mode & 0o7022 != 0 || mode & 0o111 != 0 || mode & 0o444 == 0 =>
        {
            Err(invalid(
                kind,
                "mode must be read-only outside its owner and must not be executable",
            ))
        }
        _ => Ok(()),
    }
}

fn invalid(kind: TlsFileKind, message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("TLS {} {message}", kind.label()),
    )
}

fn std_error(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn write_file(path: &Path, contents: &[u8], mode: u32) {
        std::fs::write(path, contents).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn atomic_symlink(target: &Path, link: &Path) {
        let replacement = link.with_extension("next");
        symlink(target, &replacement).unwrap();
        std::fs::rename(replacement, link).unwrap();
    }

    #[test]
    fn regular_symlink_rotation_reads_each_complete_generation() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("archive");
        let live = root.path().join("live");
        std::fs::create_dir_all(&archive).unwrap();
        std::fs::create_dir_all(&live).unwrap();
        write_file(&archive.join("cert-1.pem"), b"certificate one", 0o644);
        write_file(&archive.join("key-1.pem"), b"private key one", 0o600);
        write_file(&archive.join("cert-2.pem"), b"certificate two", 0o644);
        write_file(&archive.join("key-2.pem"), b"private key two", 0o600);
        symlink("../archive/cert-1.pem", live.join("cert.pem")).unwrap();
        symlink("../archive/key-1.pem", live.join("key.pem")).unwrap();

        let first = read_validated_tls_pem(&live.join("cert.pem"), &live.join("key.pem")).unwrap();
        assert_eq!(first.certificate_chain, b"certificate one");
        assert_eq!(first.private_key, b"private key one");

        atomic_symlink(Path::new("../archive/cert-2.pem"), &live.join("cert.pem"));
        atomic_symlink(Path::new("../archive/key-2.pem"), &live.join("key.pem"));
        let second = read_validated_tls_pem(&live.join("cert.pem"), &live.join("key.pem")).unwrap();
        assert_eq!(second.certificate_chain, b"certificate two");
        assert_eq!(second.private_key, b"private key two");
    }

    #[test]
    fn rejects_unsafe_original_or_target_parent() {
        let root = tempfile::tempdir().unwrap();
        let unsafe_directory = root.path().join("unsafe");
        std::fs::create_dir(&unsafe_directory).unwrap();
        std::fs::set_permissions(&unsafe_directory, std::fs::Permissions::from_mode(0o777))
            .unwrap();
        write_file(&unsafe_directory.join("cert.pem"), b"certificate", 0o644);
        let error = open_validated_file(
            &unsafe_directory.join("cert.pem"),
            TlsFileKind::CertificateChain,
            rustix::process::geteuid().as_raw(),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let live = root.path().join("live");
        std::fs::create_dir(&live).unwrap();
        symlink("../unsafe/cert.pem", live.join("cert.pem")).unwrap();
        assert!(open_validated_file(
            &live.join("cert.pem"),
            TlsFileKind::CertificateChain,
            rustix::process::geteuid().as_raw(),
        )
        .is_err());
    }

    #[test]
    fn owner_policy_accepts_only_root_or_service_uid() {
        assert!(validate_owner_raw(0, 1000, "test").is_ok());
        assert!(validate_owner_raw(1000, 1000, "test").is_ok());
        let error = validate_owner_raw(1001, 1000, "test").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn private_key_modes_are_exact_and_certificate_mode_is_not_writable() {
        for mode in [0o400, 0o440, 0o600, 0o640] {
            assert!(validate_file_mode(mode, TlsFileKind::PrivateKey).is_ok());
        }
        for mode in [0o000, 0o444, 0o620, 0o644, 0o660, 0o700, 0o4640] {
            assert!(validate_file_mode(mode, TlsFileKind::PrivateKey).is_err());
        }
        assert!(validate_file_mode(0o644, TlsFileKind::CertificateChain).is_ok());
        assert!(validate_file_mode(0o664, TlsFileKind::CertificateChain).is_err());
        assert!(validate_file_mode(0o755, TlsFileKind::CertificateChain).is_err());
        assert!(validate_file_mode(0o4644, TlsFileKind::CertificateChain).is_err());
    }

    #[test]
    fn rejects_hard_linked_private_key() {
        let root = tempfile::tempdir().unwrap();
        let key = root.path().join("key.pem");
        write_file(&key, b"private key", 0o600);
        std::fs::hard_link(&key, root.path().join("key-copy.pem")).unwrap();
        let error = open_validated_file(
            &key,
            TlsFileKind::PrivateKey,
            rustix::process::geteuid().as_raw(),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("exactly one hard link"));
    }

    #[test]
    fn rejects_path_swap_between_inspection_and_open() {
        let root = tempfile::tempdir().unwrap();
        let key = root.path().join("key.pem");
        let replacement = root.path().join("replacement.pem");
        write_file(&key, b"first private key", 0o600);
        write_file(&replacement, b"second private key", 0o600);
        let mut swap = || std::fs::rename(&replacement, &key).unwrap();
        let error = open_validated_file_with_hook(
            &key,
            TlsFileKind::PrivateKey,
            rustix::process::geteuid().as_raw(),
            &mut swap,
        )
        .err()
        .unwrap();
        assert!(error
            .to_string()
            .contains("changed while it was being opened"));
    }

    #[test]
    fn rejects_procfs_magic_links() {
        use std::os::fd::AsRawFd;

        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target.pem");
        write_file(&target, b"certificate", 0o644);
        let target = File::open(target).unwrap();
        let magic_target = format!("/proc/self/fd/{}", target.as_raw_fd());
        let link = root.path().join("cert.pem");
        symlink(magic_target, &link).unwrap();
        let error = open_validated_file(
            &link,
            TlsFileKind::CertificateChain,
            rustix::process::geteuid().as_raw(),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("magic link"));
    }

    #[test]
    fn detects_direct_name_replacement_after_descriptor_open() {
        let root = tempfile::tempdir().unwrap();
        let cert = root.path().join("cert.pem");
        let replacement = root.path().join("replacement.pem");
        let original = vec![b'a'; 64 * 1024];
        write_file(&cert, &original, 0o644);
        write_file(&replacement, b"replacement", 0o644);
        let service_uid = rustix::process::geteuid().as_raw();
        let opened =
            open_validated_file(&cert, TlsFileKind::CertificateChain, service_uid).unwrap();
        std::fs::rename(replacement, cert).unwrap();
        let error = opened.read(service_uid).unwrap_err();
        assert!(error
            .to_string()
            .contains("changed while it was being read"));
    }

    #[test]
    fn rejects_empty_oversized_and_non_regular_inputs() {
        let root = tempfile::tempdir().unwrap();
        let service_uid = rustix::process::geteuid().as_raw();
        let empty = root.path().join("empty.pem");
        write_file(&empty, b"", 0o644);
        assert!(open_validated_file(&empty, TlsFileKind::CertificateChain, service_uid).is_err());

        let oversized = root.path().join("oversized.pem");
        write_file(
            &oversized,
            &vec![b'x'; MAX_PRIVATE_KEY_BYTES as usize + 1],
            0o600,
        );
        assert!(open_validated_file(&oversized, TlsFileKind::PrivateKey, service_uid).is_err());

        assert!(
            open_validated_file(root.path(), TlsFileKind::CertificateChain, service_uid).is_err()
        );
    }
}
