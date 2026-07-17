use std::{fs::File, io, sync::Arc};

use crate::path_security;

use super::identity::entry_matches_identity;
use super::private_entries::{
    active_upload_fragment_guard, unregister_upload_fragment, upload_fragment_name,
    ActiveUploadFragmentKey,
};
use super::{linux, validated, EntryKind, SecureDirectory, SecureRoot};

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

impl SecureRoot {
    pub fn begin_upload(&self, directory: &str) -> io::Result<PendingUpload> {
        self.root.begin_upload(directory)
    }

    pub fn begin_staged_upload(&self) -> io::Result<PendingUpload> {
        self.root.begin_staged_upload()
    }
}

impl SecureDirectory {
    pub fn begin_upload(&self, directory: &str) -> io::Result<PendingUpload> {
        let directory = validated(directory)?;
        let destination = self.open_user_path(
            &directory,
            linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW,
        )?;
        let mut pending = PendingUpload::new(
            self.staging.as_ref().try_clone()?,
            self.allow_replace,
            self._storage_instance_lock.clone(),
        )?;
        pending.bind_destination_file(destination)?;
        Ok(pending)
    }

    /// Allocates an upload fragment without opening or creating its eventual
    /// destination. The caller can therefore finish quota admission before a
    /// user-visible directory is mutated.
    pub fn begin_staged_upload(&self) -> io::Result<PendingUpload> {
        PendingUpload::new(
            self.staging.as_ref().try_clone()?,
            self.allow_replace,
            self._storage_instance_lock.clone(),
        )
    }
}

fn upload_destination_name(name: &str) -> io::Result<&str> {
    path_security::safe_admin_filename(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "upload destination uses an invalid or private name",
        )
    })
}

pub struct PendingUpload {
    staging: File,
    destination: Option<File>,
    temporary_name: String,
    file: Option<File>,
    active_key: Option<ActiveUploadFragmentKey>,
    expected_identity: (u64, u64),
    allow_replace: bool,
    published: bool,
    _storage_instance_lock: Option<Arc<crate::StorageInstanceLock>>,
    #[cfg(test)]
    next_directory_sync_error: Option<io::ErrorKind>,
}

impl PendingUpload {
    fn new(
        staging: File,
        allow_replace: bool,
        storage_instance_lock: Option<Arc<crate::StorageInstanceLock>>,
    ) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

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
                        destination: None,
                        temporary_name,
                        file: Some(file),
                        active_key: Some(active_key),
                        expected_identity,
                        allow_replace,
                        published: false,
                        _storage_instance_lock: storage_instance_lock,
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

    /// Binds the already-staged fragment to its final directory capability.
    /// Binding is one-shot so an admitted upload cannot silently change target.
    pub fn bind_destination(&mut self, directory: &SecureDirectory) -> io::Result<()> {
        self.bind_destination_file(directory.directory.as_ref().try_clone()?)
    }

    fn bind_destination_file(&mut self, destination: File) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        if self.destination.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "upload destination is already bound",
            ));
        }
        if self.staging.metadata()?.dev() != destination.metadata()?.dev() {
            return Err(io::Error::new(
                io::ErrorKind::CrossesDevices,
                "upload staging and destination must be on the same filesystem",
            ));
        }
        self.destination = Some(destination);
        Ok(())
    }

    fn destination(&self) -> io::Result<&File> {
        self.destination.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "upload destination is not bound",
            )
        })
    }

    /// Confirms that the directory capability captured before the request body
    /// still names the directory that is currently authorized by the caller.
    /// Callers must perform this check while the storage-mutation lock is held,
    /// directly before quota commit and publication.
    pub fn destination_matches(&self, directory: &SecureDirectory) -> io::Result<bool> {
        use std::os::unix::fs::MetadataExt;

        let captured = self.destination()?.metadata()?;
        let current = directory.directory.metadata()?;
        Ok(captured.is_dir()
            && current.is_dir()
            && (captured.dev(), captured.ino()) == (current.dev(), current.ino()))
    }

    pub fn publish(&mut self, name: &str) -> io::Result<PublishOutcome> {
        let name = upload_destination_name(name)?;
        self.validate_staging_identity()?;
        let destination = self.destination()?;
        let rename =
            linux::rename_noreplace_between(&self.staging, &self.temporary_name, destination, name);
        if let Err(error) = rename {
            if entry_matches_identity(destination, name, self.expected_identity, EntryKind::File) {
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
        let destination = self.destination()?;
        let rename =
            linux::rename_replace_between(&self.staging, &self.temporary_name, destination, name);
        if let Err(error) = rename {
            if entry_matches_identity(destination, name, self.expected_identity, EntryKind::File) {
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
        self.destination()?.sync_all()?;
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
