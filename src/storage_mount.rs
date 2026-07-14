use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    os::unix::{ffi::OsStringExt, fs::MetadataExt},
    path::{Path, PathBuf},
};

use rustix::fs::{open, statx, AtFlags, Mode, OFlags, StatxFlags};
use thiserror::Error;

use crate::config::Storage;

const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

#[derive(Debug, Error)]
#[error("{0}")]
pub struct StorageMountError(String);

#[derive(Clone, Debug, Eq, PartialEq)]
struct MountInfo {
    mount_id: u64,
    device_major: u32,
    device_minor: u32,
    mount_point: PathBuf,
    read_write: bool,
    mount_options: Vec<String>,
    filesystem_type: String,
    source: OsString,
    super_options: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PathMountIdentity {
    mount_id: u64,
    device_major: u32,
    device_minor: u32,
}

#[derive(Debug)]
struct ValidatedDirectory {
    file: File,
    canonical_path: PathBuf,
    mount_identity: PathMountIdentity,
    device: u64,
    inode: u64,
}

/// Directory capabilities captured while the mount policy is validated.
///
/// Callers must hand these descriptors to the storage lock, `SecureRoot`, and
/// SQLite instead of resolving the configured paths a second time. Path
/// binding checks can detect replacement before startup continues, while the
/// descriptors make a replacement after the check unable to redirect I/O.
#[derive(Debug)]
#[doc(hidden)]
pub struct ValidatedStorage {
    root: ValidatedDirectory,
    internal: Option<ValidatedDirectory>,
    data: ValidatedDirectory,
}

impl ValidatedStorage {
    pub(crate) fn root_file(&self) -> std::io::Result<File> {
        self.root.file.try_clone()
    }

    pub(crate) fn internal_file(&self) -> std::io::Result<Option<File>> {
        self.internal
            .as_ref()
            .map(|directory| directory.file.try_clone())
            .transpose()
    }

    #[doc(hidden)]
    pub fn data_file(&self) -> std::io::Result<File> {
        self.data.file.try_clone()
    }

    pub(crate) fn root_path(&self) -> &Path {
        &self.root.canonical_path
    }

    pub(crate) fn internal_path(&self) -> Option<&Path> {
        self.internal
            .as_ref()
            .map(|directory| directory.canonical_path.as_path())
    }

    #[doc(hidden)]
    pub fn verify_path_bindings(&self, storage: &Storage) -> Result<(), StorageMountError> {
        self.root
            .verify_path_binding(&storage.root_mount_path, "root_mount_path")?;
        self.data
            .verify_path_binding(&storage.data_directory, "data_directory")?;
        match (
            self.internal.as_ref(),
            storage.internal_directory.as_deref(),
        ) {
            (Some(directory), Some(path)) => {
                directory.verify_path_binding(path, "internal_directory")?;
            }
            (Some(_), None) | (None, Some(_)) if storage.require_mount => {
                return Err(mount_error(
                    "internal_directory changed while its validated capability was handed off",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

impl ValidatedDirectory {
    fn open(path: &Path, label: &str) -> Result<Self, StorageMountError> {
        let canonical_path = fs::canonicalize(path).map_err(|error| {
            mount_error(format!(
                "cannot resolve {label} {}: {error}",
                path.display()
            ))
        })?;
        let file = open(
            &canonical_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            mount_error(format!(
                "cannot open {label} {} without following links: {error}",
                canonical_path.display()
            ))
        })?;
        let metadata = file.metadata().map_err(|error| {
            mount_error(format!(
                "cannot inspect {label} {}: {error}",
                canonical_path.display()
            ))
        })?;
        if !metadata.is_dir() {
            return Err(mount_error(format!(
                "{label} {} is not a directory",
                canonical_path.display()
            )));
        }
        let mount_identity = mount_identity_for_file(&file, &canonical_path)?;
        Ok(Self {
            file,
            canonical_path,
            mount_identity,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn verify_path_binding(&self, path: &Path, label: &str) -> Result<(), StorageMountError> {
        let current = Self::open(path, label)?;
        if current.canonical_path != self.canonical_path
            || current.mount_identity != self.mount_identity
            || current.device != self.device
            || current.inode != self.inode
        {
            return Err(mount_error(format!(
                "{label} {} no longer names the directory identity validated at startup",
                path.display()
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct IdentifiedPath<'a> {
    path: &'a Path,
    identity: PathMountIdentity,
}

fn identified(path: &Path, identity: PathMountIdentity) -> IdentifiedPath<'_> {
    IdentifiedPath { path, identity }
}

pub fn validate(storage: &Storage) -> Result<(), StorageMountError> {
    validate_and_open(storage).map(|_| ())
}

#[doc(hidden)]
pub fn validate_and_open(storage: &Storage) -> Result<ValidatedStorage, StorageMountError> {
    if !storage.require_mount {
        return reject_unconfigured_remote_storage(storage);
    }

    let root = ValidatedDirectory::open(&storage.root_mount_path, "required root_mount_path")?;
    let data = ValidatedDirectory::open(&storage.data_directory, "pre-provisioned data_directory")?;
    let internal_path = storage
        .internal_directory
        .as_deref()
        .ok_or_else(|| mount_error("internal_directory is missing"))?;
    let internal = ValidatedDirectory::open(internal_path, "pre-provisioned internal_directory")?;
    validate_canonical_relationships(
        &root.canonical_path,
        &internal.canonical_path,
        &data.canonical_path,
    )?;
    validate_service_owned_directory_capability(&root, "root_mount_path")?;
    validate_service_owned_directory_capability(&internal, "internal_directory")?;
    validate_service_owned_directory_capability(&data, "data_directory")?;
    let mountinfo = fs::read(MOUNTINFO_PATH).map_err(|error| {
        mount_error(format!(
            "cannot read the Linux mount table from {MOUNTINFO_PATH}: {error}"
        ))
    })?;
    let mounts = parse_mountinfo(&mountinfo)?;

    validate_identity(
        storage,
        identified(&root.canonical_path, root.mount_identity),
        identified(&internal.canonical_path, internal.mount_identity),
        identified(&data.canonical_path, data.mount_identity),
        &mounts,
    )?;

    let validated = ValidatedStorage {
        root,
        internal: Some(internal),
        data,
    };
    validated.verify_path_bindings(storage)?;
    Ok(validated)
}

fn reject_unconfigured_remote_storage(
    storage: &Storage,
) -> Result<ValidatedStorage, StorageMountError> {
    let root = ValidatedDirectory::open(&storage.root_mount_path, "storage root")?;
    let data = ValidatedDirectory::open(&storage.data_directory, "data_directory")?;
    validate_service_owned_directory_capability(&data, "data_directory")?;
    let mountinfo = fs::read(MOUNTINFO_PATH).map_err(|error| {
        mount_error(format!(
            "cannot read the Linux mount table from {MOUNTINFO_PATH}: {error}"
        ))
    })?;
    let mounts = parse_mountinfo(&mountinfo)?;
    let mount = unique_mount_for_identity(root.mount_identity, &mounts, &root.canonical_path)?;
    if is_remote_filesystem(&mount.filesystem_type) {
        return Err(mount_error(format!(
            "remote filesystem type {:?} requires require_mount=true, an explicit mount identity, and pre-provisioned sibling staging",
            mount.filesystem_type
        )));
    }
    let data_mount = unique_mount_for_identity(data.mount_identity, &mounts, &data.canonical_path)?;
    if is_remote_filesystem(&data_mount.filesystem_type) {
        return Err(mount_error(format!(
            "data_directory {} uses remote filesystem type {:?}; SQLite/WAL requires local storage",
            data.canonical_path.display(),
            data_mount.filesystem_type
        )));
    }
    let validated = ValidatedStorage {
        root,
        internal: None,
        data,
    };
    validated.verify_path_bindings(storage)?;
    Ok(validated)
}

fn validate_identity(
    storage: &Storage,
    root: IdentifiedPath<'_>,
    internal: IdentifiedPath<'_>,
    data: IdentifiedPath<'_>,
    mounts: &[MountInfo],
) -> Result<(), StorageMountError> {
    let (root_path, root_identity) = (root.path, root.identity);
    let (internal_path, internal_identity) = (internal.path, internal.identity);
    let (data_path, data_identity) = (data.path, data.identity);
    let mut matching_mounts = mounts
        .iter()
        .filter(|mount| mount.mount_id == root_identity.mount_id);
    let mount = matching_mounts.next().ok_or_else(|| {
        mount_error(format!(
            "mount ID {} for {} is absent from {MOUNTINFO_PATH}",
            root_identity.mount_id,
            root_path.display()
        ))
    })?;
    if matching_mounts.next().is_some() {
        return Err(mount_error(format!(
            "mount ID {} occurs more than once in {MOUNTINFO_PATH}",
            root_identity.mount_id
        )));
    }
    if mount.device_major != root_identity.device_major
        || mount.device_minor != root_identity.device_minor
    {
        return Err(mount_error(format!(
            "mount ID {} changed identity while it was being validated",
            root_identity.mount_id
        )));
    }
    if !root_path.starts_with(&mount.mount_point) {
        return Err(mount_error(format!(
            "{} is not below its validated active mount point {}",
            root_path.display(),
            mount.mount_point.display()
        )));
    }
    if internal_identity != root_identity || !internal_path.starts_with(&mount.mount_point) {
        return Err(mount_error(format!(
            "internal_directory {} and root_mount_path {} must use the same validated mount identity",
            internal_path.display(),
            root_path.display()
        )));
    }
    if internal_path.starts_with(root_path) || root_path.starts_with(internal_path) {
        return Err(mount_error(
            "internal_directory must be a sibling outside root_mount_path",
        ));
    }
    if !mount.read_write {
        return Err(mount_error(format!(
            "{} is mounted read-only; VaultLink storage requires a read-write mount",
            root_path.display()
        )));
    }

    let expected_filesystem_type = storage
        .expected_filesystem_type
        .as_deref()
        .ok_or_else(|| mount_error("expected_filesystem_type is missing"))?;
    if mount.filesystem_type != expected_filesystem_type {
        return Err(mount_error(format!(
            "{} has filesystem type {:?}, expected {:?}",
            root_path.display(),
            mount.filesystem_type,
            expected_filesystem_type
        )));
    }

    let expected_source = storage
        .expected_mount_source
        .as_deref()
        .ok_or_else(|| mount_error("expected_mount_source is missing"))?;
    if mount.source != OsStr::new(expected_source) {
        return Err(mount_error(format!(
            "{} has mount source {:?}, expected {:?}",
            root_path.display(),
            mount.source,
            expected_source
        )));
    }

    if matches!(expected_filesystem_type, "cifs" | "smb3") {
        validate_cifs_options(mount)?;
    } else if !is_local_sqlite_filesystem(expected_filesystem_type) {
        return Err(mount_error(format!(
            "filesystem type {expected_filesystem_type:?} has no audited VaultLink mount policy"
        )));
    }

    if matches!(expected_filesystem_type, "cifs" | "smb3")
        && (root_identity.mount_id == data_identity.mount_id
            || (root_identity.device_major == data_identity.device_major
                && root_identity.device_minor == data_identity.device_minor))
    {
        return Err(mount_error(format!(
            "data_directory {} resolves to the same external mount identity as root_mount_path (root mount ID {}, data mount ID {}, device {}:{}); SQLite state must remain on a separate filesystem",
            data_path.display(),
            root_identity.mount_id,
            data_identity.mount_id,
            root_identity.device_major,
            root_identity.device_minor
        )));
    }

    let data_mount = unique_mount_for_identity(data_identity, mounts, data_path)?;
    if !is_local_sqlite_filesystem(&data_mount.filesystem_type) {
        return Err(mount_error(format!(
            "data_directory {} uses unsupported non-local filesystem type {:?}; SQLite/WAL requires a local filesystem",
            data_path.display(),
            data_mount.filesystem_type
        )));
    }

    Ok(())
}

fn unique_mount_for_identity<'a>(
    identity: PathMountIdentity,
    mounts: &'a [MountInfo],
    path: &Path,
) -> Result<&'a MountInfo, StorageMountError> {
    let mut matches = mounts
        .iter()
        .filter(|mount| mount.mount_id == identity.mount_id);
    let mount = matches.next().ok_or_else(|| {
        mount_error(format!(
            "mount ID {} for {} is absent from {MOUNTINFO_PATH}",
            identity.mount_id,
            path.display()
        ))
    })?;
    if matches.next().is_some()
        || mount.device_major != identity.device_major
        || mount.device_minor != identity.device_minor
    {
        return Err(mount_error(format!(
            "mount identity for {} changed while it was being validated",
            path.display()
        )));
    }
    Ok(mount)
}

fn validate_cifs_options(mount: &MountInfo) -> Result<(), StorageMountError> {
    let has_option = |required: &str| {
        mount.mount_options.iter().any(|option| option == required)
            || mount.super_options.iter().any(|option| option == required)
    };
    for required in [
        "nosuid",
        "nodev",
        "noexec",
        "vers=3.1.1",
        "cache=strict",
        "sign",
        "seal",
        "serverino",
    ] {
        if !has_option(required) {
            return Err(mount_error(format!(
                "CIFS mount {} is missing required security option {required:?}",
                mount.mount_point.display()
            )));
        }
    }
    for forbidden in [
        "cache=loose",
        "nostrictsync",
        "noperm",
        "noserverino",
        "multiuser",
    ] {
        if has_option(forbidden) {
            return Err(mount_error(format!(
                "CIFS mount {} uses forbidden option {forbidden:?}",
                mount.mount_point.display()
            )));
        }
    }
    Ok(())
}

fn is_local_sqlite_filesystem(filesystem_type: &str) -> bool {
    matches!(
        filesystem_type,
        "ext2" | "ext3" | "ext4" | "xfs" | "btrfs" | "f2fs" | "bcachefs" | "zfs"
    )
}

fn is_remote_filesystem(filesystem_type: &str) -> bool {
    matches!(
        filesystem_type,
        "cifs" | "smb3" | "nfs" | "nfs4" | "9p" | "ceph" | "glusterfs" | "fuse.sshfs"
    )
}

fn mount_identity_for_file(
    file: &File,
    display_path: &Path,
) -> Result<PathMountIdentity, StorageMountError> {
    let stat = statx(
        file,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
        StatxFlags::MNT_ID | StatxFlags::BASIC_STATS,
    )
    .map_err(|error| {
        mount_error(format!(
            "cannot obtain the Linux mount ID for {} from its open directory capability: {error}",
            display_path.display()
        ))
    })?;
    if stat.stx_mask & StatxFlags::MNT_ID.bits() == 0 {
        return Err(mount_error(format!(
            "the kernel did not return a mount ID for {}; secure storage startup needs Linux statx mount-ID support",
            display_path.display()
        )));
    }
    Ok(PathMountIdentity {
        mount_id: stat.stx_mnt_id,
        device_major: stat.stx_dev_major,
        device_minor: stat.stx_dev_minor,
    })
}

fn validate_canonical_relationships(
    root: &Path,
    internal: &Path,
    data: &Path,
) -> Result<(), StorageMountError> {
    if data.starts_with(root) {
        return Err(mount_error(format!(
            "data_directory {} resolves inside the user-visible root_mount_path {}",
            data.display(),
            root.display()
        )));
    }
    if internal.starts_with(root) || root.starts_with(internal) {
        return Err(mount_error(
            "internal_directory must resolve to a sibling outside root_mount_path",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_service_owned_directory(path: &Path, label: &str) -> Result<(), StorageMountError> {
    let metadata = fs::metadata(path).map_err(|error| {
        mount_error(format!(
            "cannot inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(mount_error(format!(
            "{label} {} is not a directory",
            path.display()
        )));
    }
    let effective_uid = rustix::process::geteuid().as_raw();
    if metadata.uid() != effective_uid {
        return Err(mount_error(format!(
            "{label} {} must be owned by the VaultLink service uid {effective_uid}",
            path.display()
        )));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(mount_error(format!(
            "{label} {} must not be writable by group, other users, or a POSIX ACL mask",
            path.display()
        )));
    }
    Ok(())
}

fn validate_service_owned_directory_capability(
    directory: &ValidatedDirectory,
    label: &str,
) -> Result<(), StorageMountError> {
    let metadata = directory.file.metadata().map_err(|error| {
        mount_error(format!(
            "cannot inspect {label} {} through its validated capability: {error}",
            directory.canonical_path.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(mount_error(format!(
            "{label} {} is not a directory",
            directory.canonical_path.display()
        )));
    }
    let effective_uid = rustix::process::geteuid().as_raw();
    if metadata.uid() != effective_uid {
        return Err(mount_error(format!(
            "{label} {} must be owned by the VaultLink service uid {effective_uid}",
            directory.canonical_path.display()
        )));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(mount_error(format!(
            "{label} {} must not be writable by group, other users, or a POSIX ACL mask",
            directory.canonical_path.display()
        )));
    }
    Ok(())
}

fn parse_mountinfo(input: &[u8]) -> Result<Vec<MountInfo>, StorageMountError> {
    let mut mounts = Vec::new();
    for (line_number, line) in input.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let separator = line
            .windows(3)
            .position(|window| window == b" - ")
            .ok_or_else(|| malformed_mountinfo(line_number + 1, "missing field separator"))?;
        let left = split_fields(&line[..separator]);
        let right = split_fields(&line[separator + 3..]);
        if left.len() < 6 || right.len() < 3 {
            return Err(malformed_mountinfo(
                line_number + 1,
                "missing required fields",
            ));
        }

        let mount_id = parse_ascii_u64(left[0]).ok_or_else(|| {
            malformed_mountinfo(line_number + 1, "mount ID is not an unsigned integer")
        })?;
        let (device_major, device_minor) = parse_device(left[2])
            .ok_or_else(|| malformed_mountinfo(line_number + 1, "device ID is not major:minor"))?;
        let mount_point = PathBuf::from(OsString::from_vec(unescape_field(
            left[4],
            line_number + 1,
        )?));
        let mount_options = parse_options(left[5], line_number + 1)?;
        let read_write = mount_options.iter().any(|flag| flag == "rw");
        let filesystem_type = std::str::from_utf8(right[0])
            .map_err(|_| malformed_mountinfo(line_number + 1, "filesystem type is not UTF-8"))?
            .to_string();
        let source = OsString::from_vec(unescape_field(right[1], line_number + 1)?);
        let super_options = parse_options(right[2], line_number + 1)?;
        mounts.push(MountInfo {
            mount_id,
            device_major,
            device_minor,
            mount_point,
            read_write,
            mount_options,
            filesystem_type,
            source,
            super_options,
        });
    }
    if mounts.is_empty() {
        return Err(mount_error(format!(
            "{MOUNTINFO_PATH} contains no mount entries"
        )));
    }
    Ok(mounts)
}

fn split_fields(line: &[u8]) -> Vec<&[u8]> {
    line.split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect()
}

fn parse_options(value: &[u8], line_number: usize) -> Result<Vec<String>, StorageMountError> {
    let value = std::str::from_utf8(value)
        .map_err(|_| malformed_mountinfo(line_number, "mount options are not UTF-8"))?;
    Ok(value.split(',').map(str::to_string).collect())
}

fn parse_ascii_u64(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    value.iter().try_fold(0_u64, |number, byte| {
        let digit = byte.checked_sub(b'0')?;
        if digit > 9 {
            return None;
        }
        number.checked_mul(10)?.checked_add(u64::from(digit))
    })
}

fn parse_device(value: &[u8]) -> Option<(u32, u32)> {
    let separator = value.iter().position(|byte| *byte == b':')?;
    if value[separator + 1..].contains(&b':') {
        return None;
    }
    let major = u32::try_from(parse_ascii_u64(&value[..separator])?).ok()?;
    let minor = u32::try_from(parse_ascii_u64(&value[separator + 1..])?).ok()?;
    Some((major, minor))
}

fn unescape_field(value: &[u8], line_number: usize) -> Result<Vec<u8>, StorageMountError> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'\\' {
            decoded.push(value[index]);
            index += 1;
            continue;
        }
        if index + 3 >= value.len()
            || !value[index + 1..=index + 3]
                .iter()
                .all(|byte| matches!(*byte, b'0'..=b'7'))
        {
            return Err(malformed_mountinfo(
                line_number,
                "invalid octal escape in mount field",
            ));
        }
        let byte = u16::from(value[index + 1] - b'0') * 64
            + u16::from(value[index + 2] - b'0') * 8
            + u16::from(value[index + 3] - b'0');
        decoded.push(
            u8::try_from(byte)
                .map_err(|_| malformed_mountinfo(line_number, "octal escape exceeds one byte"))?,
        );
        index += 4;
    }
    Ok(decoded)
}

fn malformed_mountinfo(line_number: usize, detail: &str) -> StorageMountError {
    mount_error(format!(
        "cannot parse {MOUNTINFO_PATH} line {line_number}: {detail}"
    ))
}

fn mount_error(message: impl Into<String>) -> StorageMountError {
    StorageMountError(format!(
        "storage mount validation failed closed: {}",
        message.into()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage() -> Storage {
        Storage {
            root_mount_path: "/mnt/vault link".into(),
            data_directory: "/var/lib/vaultlink".into(),
            internal_directory: Some("/mnt/.vaultlink-internal".into()),
            require_mount: true,
            external_writers: true,
            expected_filesystem_type: Some("cifs".into()),
            expected_mount_source: Some("//nas.example/vault link".into()),
            max_upload_size: 1,
            max_zip_size: 0,
            max_zip_files: 0,
            max_search_entries: 1,
            max_search_results: 1,
            max_preview_size: 1,
            preview_extensions: vec![],
            image_preview_extensions: vec![],
            pdf_preview_enabled: false,
            max_media_preview_size: 1,
            blocked_extensions: vec![],
        }
    }

    fn mounts() -> Vec<MountInfo> {
        parse_mountinfo(
            b"41 23 0:42 / /mnt rw,nosuid,nodev,noexec,relatime - cifs //nas.example/vault\\040link rw,vers=3.1.1,cache=strict,sign,seal,serverino\n\
              23 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n",
        )
        .unwrap()
    }

    fn identity(mount_id: u64, device_major: u32, device_minor: u32) -> PathMountIdentity {
        PathMountIdentity {
            mount_id,
            device_major,
            device_minor,
        }
    }

    fn location(
        path: &'static str,
        mount_id: u64,
        device_major: u32,
        device_minor: u32,
    ) -> IdentifiedPath<'static> {
        identified(
            Path::new(path),
            identity(mount_id, device_major, device_minor),
        )
    }

    fn unmounted_storage(root: &Path, data: &Path) -> Storage {
        let mut storage = storage();
        storage.root_mount_path = root.to_path_buf();
        storage.data_directory = data.to_path_buf();
        storage.internal_directory = None;
        storage.require_mount = false;
        storage.external_writers = false;
        storage.expected_filesystem_type = None;
        storage.expected_mount_source = None;
        storage
    }

    #[test]
    fn parses_escaped_mount_identity() {
        let mounts = mounts();
        assert_eq!(mounts[0].mount_id, 41);
        assert_eq!((mounts[0].device_major, mounts[0].device_minor), (0, 42));
        assert_eq!(mounts[0].mount_point, Path::new("/mnt"));
        assert!(mounts[0].read_write);
        assert_eq!(mounts[0].filesystem_type, "cifs");
        assert_eq!(mounts[0].source, OsStr::new("//nas.example/vault link"));
    }

    #[test]
    fn validated_root_capability_detects_a_path_replacement() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        let displaced = parent.path().join("root-validated");
        let data = parent.path().join("data");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&data).unwrap();
        let storage = unmounted_storage(&root, &data);
        let validated = validate_and_open(&storage).unwrap();

        std::fs::rename(&root, &displaced).unwrap();
        std::fs::create_dir(&root).unwrap();

        let error = validated.verify_path_bindings(&storage).unwrap_err();
        assert!(error.to_string().contains("root_mount_path"));
        assert_eq!(
            validated.root.file.metadata().unwrap().ino(),
            std::fs::metadata(&displaced).unwrap().ino()
        );
        assert_ne!(
            validated.root.file.metadata().unwrap().ino(),
            std::fs::metadata(&root).unwrap().ino()
        );
    }

    #[test]
    fn validated_data_capability_detects_a_path_replacement() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        let data = parent.path().join("data");
        let displaced = parent.path().join("data-validated");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&data).unwrap();
        let storage = unmounted_storage(&root, &data);
        let validated = validate_and_open(&storage).unwrap();

        std::fs::rename(&data, &displaced).unwrap();
        std::fs::create_dir(&data).unwrap();

        let error = validated.verify_path_bindings(&storage).unwrap_err();
        assert!(error.to_string().contains("data_directory"));
        assert_eq!(
            validated.data.file.metadata().unwrap().ino(),
            std::fs::metadata(&displaced).unwrap().ino()
        );
        assert_ne!(
            validated.data.file.metadata().unwrap().ino(),
            std::fs::metadata(&data).unwrap().ino()
        );
    }

    #[test]
    fn accepts_exact_mount_and_separate_data_mount_ids() {
        validate_identity(
            &storage(),
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &mounts(),
        )
        .unwrap();
    }

    #[test]
    fn accepts_audited_local_storage_and_sqlite_on_the_same_mount() {
        let local_mounts = parse_mountinfo(
            b"23 1 8:2 / / rw,nosuid,nodev,relatime - ext4 /dev/mapper/vaultlink rw\n",
        )
        .unwrap();
        let mut local = storage();
        local.root_mount_path = "/srv/vaultlink/shared".into();
        local.internal_directory = Some("/srv/vaultlink/.vaultlink-internal".into());
        local.data_directory = "/var/lib/vaultlink".into();
        local.external_writers = false;
        local.expected_filesystem_type = Some("ext4".into());
        local.expected_mount_source = Some("/dev/mapper/vaultlink".into());

        validate_identity(
            &local,
            location("/srv/vaultlink/shared", 23, 8, 2),
            location("/srv/vaultlink/.vaultlink-internal", 23, 8, 2),
            location("/var/lib/vaultlink", 23, 8, 2),
            &local_mounts,
        )
        .unwrap();
    }

    #[test]
    fn rejects_local_filesystems_outside_the_audited_allowlist() {
        let overlay_mounts = parse_mountinfo(
            b"23 1 0:99 / / rw,nosuid,nodev - overlay overlay rw,lowerdir=/lower,upperdir=/upper,workdir=/work\n",
        )
        .unwrap();
        let mut local = storage();
        local.root_mount_path = "/srv/vaultlink/shared".into();
        local.internal_directory = Some("/srv/vaultlink/.vaultlink-internal".into());
        local.data_directory = "/var/lib/vaultlink".into();
        local.external_writers = false;
        local.expected_filesystem_type = Some("overlay".into());
        local.expected_mount_source = Some("overlay".into());

        let error = validate_identity(
            &local,
            location("/srv/vaultlink/shared", 23, 0, 99),
            location("/srv/vaultlink/.vaultlink-internal", 23, 0, 99),
            location("/var/lib/vaultlink", 23, 0, 99),
            &overlay_mounts,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("no audited VaultLink mount policy"));
    }

    #[test]
    fn rejects_a_canonical_data_directory_inside_the_visible_root() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("shared");
        let internal = directory.path().join(".vaultlink-internal");
        let data = root.join("state");
        let data_alias = directory.path().join("state-alias");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&internal).unwrap();
        std::fs::create_dir(&data).unwrap();
        symlink(&data, &data_alias).unwrap();

        let error = validate_canonical_relationships(
            &root.canonicalize().unwrap(),
            &internal.canonicalize().unwrap(),
            &data_alias.canonicalize().unwrap(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("user-visible root_mount_path"));
    }

    #[test]
    fn rejects_group_or_acl_mask_writable_service_directories() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let error =
            validate_service_owned_directory(directory.path(), "root_mount_path").unwrap_err();
        assert!(error.to_string().contains("POSIX ACL mask"));

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        validate_service_owned_directory(directory.path(), "root_mount_path").unwrap();
    }

    #[test]
    fn rejects_local_fallback_wrong_source_and_wrong_type() {
        let mut local_fallback = mounts();
        local_fallback[0].filesystem_type = "ext4".into();
        local_fallback[0].source = "/dev/sdb1".into();
        let error = validate_identity(
            &storage(),
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &local_fallback,
        )
        .unwrap_err();
        assert!(error.to_string().contains("filesystem type"));

        let mut wrong_source = storage();
        wrong_source.expected_mount_source = Some("//other.example/vault".into());
        let error = validate_identity(
            &wrong_source,
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &mounts(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("mount source"));
    }

    #[test]
    fn rejects_read_only_external_mount() {
        let mut read_only = mounts();
        read_only[0].read_write = false;
        let error = validate_identity(
            &storage(),
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &read_only,
        )
        .unwrap_err();
        assert!(error.to_string().contains("read-only"));
    }

    #[test]
    fn rejects_weak_or_incoherent_cifs_options() {
        for forbidden in ["cache=loose", "nostrictsync", "noperm", "multiuser"] {
            let mut weak = mounts();
            weak[0].super_options.push(forbidden.into());
            let error = validate_identity(
                &storage(),
                location("/mnt/vault link", 41, 0, 42),
                location("/mnt/.vaultlink-internal", 41, 0, 42),
                location("/var/lib", 23, 8, 2),
                &weak,
            )
            .unwrap_err();
            assert!(error.to_string().contains("forbidden option"));
        }

        let mut missing_encryption = mounts();
        missing_encryption[0]
            .super_options
            .retain(|option| option != "seal");
        let error = validate_identity(
            &storage(),
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &missing_encryption,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("missing required security option"));
    }

    #[test]
    fn rejects_network_filesystem_for_sqlite() {
        let mut remote_data = mounts();
        remote_data[1].filesystem_type = "nfs4".into();
        remote_data[1].source = "nas:/state".into();
        let error = validate_identity(
            &storage(),
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &remote_data,
        )
        .unwrap_err();
        assert!(error.to_string().contains("SQLite/WAL"));
    }

    #[test]
    fn rejects_path_outside_the_validated_mountpoint() {
        let error = validate_identity(
            &storage(),
            location("/srv/local-fallback", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib", 23, 8, 2),
            &mounts(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("not below"));
    }

    #[test]
    fn rejects_sqlite_state_on_same_mount_id() {
        let error = validate_identity(
            &storage(),
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/mnt/vault link/.state", 41, 0, 42),
            &mounts(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("SQLite state"));
    }

    #[test]
    fn rejects_bind_mount_of_same_external_filesystem_for_sqlite() {
        let error = validate_identity(
            &storage(),
            location("/mnt/vault link", 41, 0, 42),
            location("/mnt/.vaultlink-internal", 41, 0, 42),
            location("/var/lib/vaultlink", 99, 0, 42),
            &mounts(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("same external mount identity"));
    }

    #[test]
    fn malformed_mountinfo_fails_closed() {
        assert!(parse_mountinfo(b"41 incomplete\n").is_err());
        assert!(parse_mountinfo(b"41 23 0:42 / /mnt/bad\\99 rw - cifs //nas/share rw\n").is_err());
    }
}
