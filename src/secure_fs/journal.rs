use std::{ffi::OsStr, fs::File, io};

use super::{
    deletion_manifest_name, file_operation_name, is_file_operation_name, linux, DurableDeletePhase,
    DurableFileOperation, FileOperationWriteError,
};

pub(super) fn write_pending_manifest(
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

pub(super) fn write_file_operation(
    staging: &File,
    operation: &DurableFileOperation,
) -> Result<String, FileOperationWriteError> {
    use std::io::Write;

    for _ in 0..16 {
        let operation_name = file_operation_name();
        let temporary_name = format!("{operation_name}.pending");
        let mut manifest = match linux::openat2(
            staging,
            &temporary_name,
            linux::O_WRONLY | linux::O_CREAT | linux::O_EXCL,
        ) {
            Ok(manifest) => manifest,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(FileOperationWriteError::before_publish(error)),
        };
        let mut published = false;
        let result = (|| {
            serde_json::to_writer(&mut manifest, operation).map_err(io::Error::other)?;
            manifest.write_all(b"\n")?;
            manifest.sync_all()?;
            linux::rename_noreplace(staging, &temporary_name, &operation_name)?;
            published = true;
            staging.sync_all()
        })();
        if let Err(error) = result {
            if !published {
                drop(manifest);
                let _ = linux::unlink(staging, &temporary_name);
                let _ = staging.sync_all();
                if error.kind() == io::ErrorKind::AlreadyExists {
                    continue;
                }
            }
            return Err(FileOperationWriteError {
                error,
                published_name: published.then_some(operation_name),
            });
        }
        return Ok(operation_name);
    }
    Err(FileOperationWriteError::before_publish(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate durable file-operation journal",
    )))
}

pub(super) fn replace_file_operation(
    staging: &File,
    operation_name: &str,
    operation: &DurableFileOperation,
) -> io::Result<()> {
    use std::io::Write;

    if !is_file_operation_name(OsStr::new(operation_name)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid file-operation journal name",
        ));
    }
    let temporary_name = format!("{operation_name}.pending");
    let mut manifest = linux::openat2(
        staging,
        &temporary_name,
        linux::O_WRONLY | linux::O_CREAT | linux::O_EXCL,
    )?;
    let mut published = false;
    let result = (|| {
        serde_json::to_writer(&mut manifest, operation).map_err(io::Error::other)?;
        manifest.write_all(b"\n")?;
        manifest.sync_all()?;
        linux::rename_replace_between(staging, &temporary_name, staging, operation_name)?;
        published = true;
        staging.sync_all()
    })();
    if result.is_err() && !published {
        drop(manifest);
        let _ = linux::unlink(staging, &temporary_name);
        let _ = staging.sync_all();
    }
    result
}

pub(super) fn replace_delete_operation_phase(
    staging: &File,
    operation_name: &str,
    phase: DurableDeletePhase,
) -> io::Result<()> {
    let mut operation = read_file_operation(staging, operation_name)?;
    match &mut operation {
        DurableFileOperation::Delete {
            phase: current_phase,
            ..
        } => *current_phase = phase,
        DurableFileOperation::Rename { .. } => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "delete transaction references a rename journal",
            ));
        }
    }
    replace_file_operation(staging, operation_name, &operation)
}

pub(super) fn read_file_operation(
    staging: &File,
    operation_name: &str,
) -> io::Result<DurableFileOperation> {
    use std::io::Read;

    const MAX_OPERATION_BYTES: u64 = 64 * 1024;
    let mut manifest =
        linux::openat2(staging, operation_name, linux::O_RDONLY | linux::O_NOFOLLOW)?;
    let metadata = manifest.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_OPERATION_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file-operation journal is not a small regular file",
        ));
    }
    let mut content = Vec::with_capacity(metadata.len() as usize);
    manifest
        .by_ref()
        .take(MAX_OPERATION_BYTES + 1)
        .read_to_end(&mut content)?;
    if content.len() as u64 > MAX_OPERATION_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file-operation journal exceeds its size limit",
        ));
    }
    serde_json::from_slice(&content).map_err(io::Error::other)
}

pub(super) fn remove_file_operation(staging: &File, operation_name: &str) -> io::Result<()> {
    match linux::unlink(staging, operation_name) {
        Ok(()) => staging.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn read_pending_manifest(staging: &File, manifest_name: &str) -> io::Result<String> {
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

pub(super) fn remove_pending_manifest(staging: &File, manifest_name: &str) -> io::Result<()> {
    match linux::unlink(staging, manifest_name) {
        Ok(()) => staging.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
