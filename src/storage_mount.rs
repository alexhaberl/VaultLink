use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    os::unix::{ffi::OsStringExt, fs::MetadataExt},
    path::{Path, PathBuf},
};

use rustix::fs::{open, statx, AtFlags, Mode, OFlags, StatxFlags};
use thiserror::Error;

use crate::{
    config::{Storage, DEFAULT_INTERNAL_DIRECTORY_NAME},
    path_security,
};

const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

#[derive(Debug, Error)]
#[error("{0}")]
pub struct StorageMountError(String);

#[derive(Clone, Debug, Eq, PartialEq)]
struct MountInfo {
    mount_id: u64,
    mount_point: PathBuf,
    read_write: bool,
    mount_options: Vec<String>,
    filesystem_type: String,
    source: OsString,
    super_options: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveMount {
    pub mount_point: PathBuf,
    pub filesystem_type: String,
    pub source: String,
    pub read_write: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectedMount {
    pub mount_point: PathBuf,
    pub root_mount_path: PathBuf,
    pub internal_directory: PathBuf,
    pub filesystem_type: String,
    pub source: String,
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

pub fn active_mount_at(path: &Path) -> Result<Option<ActiveMount>, StorageMountError> {
    let mountinfo = fs::read(MOUNTINFO_PATH).map_err(|error| {
        mount_error(format!(
            "cannot read the Linux mount table from {MOUNTINFO_PATH}: {error}"
        ))
    })?;
    active_mount_at_from(&mountinfo, path)
}

pub fn discover_supported_mounts() -> Result<Vec<DetectedMount>, StorageMountError> {
    let mountinfo = fs::read(MOUNTINFO_PATH).map_err(|error| {
        mount_error(format!(
            "cannot read the Linux mount table from {MOUNTINFO_PATH}: {error}"
        ))
    })?;
    let mut mounts = discover_supported_mounts_from(&mountinfo)?;
    mounts.retain(|mount| mount_point_is_directory(&mount.mount_point));
    Ok(mounts)
}

fn mount_point_is_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
}

fn active_mount_at_from(
    mountinfo: &[u8],
    path: &Path,
) -> Result<Option<ActiveMount>, StorageMountError> {
    let mut matches = parse_mountinfo(mountinfo)?
        .into_iter()
        .filter(|mount| mount.mount_point == path);
    let Some(mount) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(mount_error(format!(
            "mount point {} occurs more than once in {MOUNTINFO_PATH}",
            path.display()
        )));
    }
    let source = mount.source.into_string().map_err(|_| {
        mount_error(format!(
            "mount source for {} is not valid UTF-8",
            path.display()
        ))
    })?;
    Ok(Some(ActiveMount {
        mount_point: mount.mount_point,
        filesystem_type: mount.filesystem_type,
        source,
        read_write: mount.read_write,
    }))
}

fn discover_supported_mounts_from(
    mountinfo: &[u8],
) -> Result<Vec<DetectedMount>, StorageMountError> {
    let mut detected = Vec::new();
    for mount in parse_mountinfo(mountinfo)? {
        let cifs = matches!(mount.filesystem_type.as_str(), "cifs" | "smb3");
        let supported = cifs || is_local_sqlite_filesystem(&mount.filesystem_type);
        if !supported || !mount.read_write || (cifs && validate_cifs_options(&mount).is_err()) {
            continue;
        }
        let Ok(source) = mount.source.into_string() else {
            continue;
        };
        let root_mount_path = if cifs {
            mount.mount_point.clone()
        } else {
            mount.mount_point.join("shared")
        };
        let internal_directory = mount.mount_point.join(DEFAULT_INTERNAL_DIRECTORY_NAME);
        detected.push(DetectedMount {
            mount_point: mount.mount_point,
            root_mount_path,
            internal_directory,
            filesystem_type: if cifs {
                "cifs".to_string()
            } else {
                mount.filesystem_type
            },
            source,
        });
    }
    detected.sort_by(|left, right| left.mount_point.cmp(&right.mount_point));
    detected.dedup_by(|left, right| left.mount_point == right.mount_point);
    Ok(detected)
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
        storage.internal_directory_is_nested(),
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

#[cfg(test)]
pub(crate) fn validate_and_open_without_mount_policy(
    storage: &Storage,
) -> Result<ValidatedStorage, StorageMountError> {
    let root = ValidatedDirectory::open(&storage.root_mount_path, "test root_mount_path")?;
    let data = ValidatedDirectory::open(&storage.data_directory, "test data_directory")?;
    let internal_path = storage
        .internal_directory
        .as_deref()
        .ok_or_else(|| mount_error("internal_directory is missing"))?;
    let internal = ValidatedDirectory::open(internal_path, "test internal_directory")?;
    validate_canonical_relationships(
        &root.canonical_path,
        &internal.canonical_path,
        &data.canonical_path,
        storage.internal_directory_is_nested(),
    )?;
    validate_service_owned_directory_capability(&root, "root_mount_path")?;
    validate_service_owned_directory_capability(&internal, "internal_directory")?;
    validate_service_owned_directory_capability(&data, "data_directory")?;

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
            "remote filesystem type {:?} requires require_mount=true, an explicit mount identity, and pre-provisioned private staging",
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
    let mount = unique_mount_for_identity(root_identity, mounts, root_path)?;
    if internal_identity != root_identity || !internal_path.starts_with(&mount.mount_point) {
        return Err(mount_error(format!(
            "internal_directory {} and root_mount_path {} must use the same validated mount identity",
            internal_path.display(),
            root_path.display()
        )));
    }
    validate_internal_relationship(
        root_path,
        internal_path,
        storage.internal_directory_is_nested(),
    )?;
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
    if !filesystem_types_match(&mount.filesystem_type, expected_filesystem_type) {
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
    if matches.next().is_some() {
        return Err(mount_error(format!(
            "mount ID {} for {} occurs more than once in {MOUNTINFO_PATH}",
            identity.mount_id,
            path.display(),
        )));
    }
    // STATX_MNT_ID is the kernel-defined key for field 1 of mountinfo.  The
    // device numbers are deliberately not cross-compared here: filesystems
    // such as Btrfs return a per-subvolume ("cooked") st_dev from getattr,
    // while mountinfo field 3 reports the superblock ("raw") device.  The
    // opened directory capability pins the mount while this lookup runs, and
    // the complete statx identity, st_dev, and inode are checked again when
    // the configured path binding is handed off.
    if !path.starts_with(&mount.mount_point) {
        return Err(mount_error(format!(
            "{} is not below its validated active mount point {}",
            path.display(),
            mount.mount_point.display()
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

fn filesystem_types_match(actual: &str, expected: &str) -> bool {
    actual == expected || (matches!(actual, "cifs" | "smb3") && matches!(expected, "cifs" | "smb3"))
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
    allow_nested_internal: bool,
) -> Result<(), StorageMountError> {
    if data.starts_with(root) {
        return Err(mount_error(format!(
            "data_directory {} resolves inside the user-visible root_mount_path {}",
            data.display(),
            root.display()
        )));
    }
    validate_internal_relationship(root, internal, allow_nested_internal)?;
    Ok(())
}

fn validate_internal_relationship(
    root: &Path,
    internal: &Path,
    allow_nested_internal: bool,
) -> Result<(), StorageMountError> {
    if allow_nested_internal {
        let direct_reserved_child = internal.parent() == Some(root)
            && internal
                .file_name()
                .is_some_and(path_security::is_internal_storage_name);
        if !direct_reserved_child {
            return Err(mount_error(
                "nested internal_directory must be the direct reserved .vaultlink-internal child of root_mount_path",
            ));
        }
    } else if internal.starts_with(root) || root.starts_with(internal) {
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
        parse_device(left[2])
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
include!("storage_mount/tests.rs");
