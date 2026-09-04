use std::{fs::File, io, sync::Arc};

use crate::path_security;

use super::identity::entry_identity_state;
use super::private_entries::{
    active_upload_fragment_guard, unregister_upload_fragment, upload_fragment_name,
    ActiveUploadFragmentKey,
};
use super::{linux, validated, EntryIdentityState, EntryKind, SecureDirectory, SecureRoot};

#[derive(Debug)]
pub enum PublishOutcome {
    Durable,
    PublishedSyncUncertain(io::Error),
    /// The publication syscall may have changed the visible namespace, but an
    /// I/O failure prevented a conclusive identity probe. Callers must treat
    /// this as a completed, audit-worthy mutation whose durability is
    /// uncertain, never as a retryable pre-publication failure.
    PublishedUncertain(io::Error),
}

impl PublishOutcome {
    pub fn is_durable(&self) -> bool {
        matches!(self, Self::Durable)
    }

    pub fn uncertainty_error(&self) -> Option<&io::Error> {
        match self {
            Self::Durable => None,
            Self::PublishedSyncUncertain(error) | Self::PublishedUncertain(error) => Some(error),
        }
    }

    pub fn sync_error(&self) -> Option<&io::Error> {
        self.uncertainty_error()
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
        self.transfer_publication_faults(&mut pending);
        pending.bind_destination_file(destination)?;
        Ok(pending)
    }

    /// Allocates an upload fragment without opening or creating its eventual
    /// destination. The caller can therefore finish quota admission before a
    /// user-visible directory is mutated.
    pub fn begin_staged_upload(&self) -> io::Result<PendingUpload> {
        let mut pending = PendingUpload::new(
            self.staging.as_ref().try_clone()?,
            self.allow_replace,
            self._storage_instance_lock.clone(),
        )?;
        self.transfer_publication_faults(&mut pending);
        Ok(pending)
    }

    fn transfer_publication_faults(&self, pending: &mut PendingUpload) {
        #[cfg(test)]
        {
            if let Some(kind) = self
                .next_upload_publication_rename_error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
            {
                pending.fail_next_publication_rename_after_success(kind);
            }
            if let Some((kind, count)) = self
                .next_upload_publication_identity_probe_errors
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
            {
                pending.fail_next_publication_identity_probes(kind, count);
            }
        }
        #[cfg(not(test))]
        let _ = pending;
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
    #[cfg(test)]
    next_publication_rename_error: Option<io::ErrorKind>,
    #[cfg(test)]
    next_publication_identity_probe_errors: Option<(io::ErrorKind, usize)>,
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
                        #[cfg(test)]
                        next_publication_rename_error: None,
                        #[cfg(test)]
                        next_publication_identity_probe_errors: None,
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
        let destination = self.destination()?.try_clone()?;
        let rename = linux::rename_noreplace_between(
            &self.staging,
            &self.temporary_name,
            &destination,
            name,
        );
        #[cfg(test)]
        let rename = self.inject_publication_rename_response_loss(rename);
        if let Err(error) = rename {
            return self.reconcile_publication_error(&destination, name, error);
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
        let destination = self.destination()?.try_clone()?;
        let rename =
            linux::rename_replace_between(&self.staging, &self.temporary_name, &destination, name);
        #[cfg(test)]
        let rename = self.inject_publication_rename_response_loss(rename);
        if let Err(error) = rename {
            return self.reconcile_publication_error(&destination, name, error);
        }
        Ok(self.finish_publication())
    }

    fn reconcile_publication_error(
        &mut self,
        destination: &File,
        name: &str,
        rename_error: io::Error,
    ) -> io::Result<PublishOutcome> {
        let destination_state = self.publication_identity_state(destination, name);
        if matches!(&destination_state, Ok(EntryIdentityState::Expected)) {
            tracing::warn!(%rename_error, destination = %name, "upload rename returned an error after publication; continuing with verified identity");
            return Ok(self.finish_publication());
        }

        let staging_state = self.staging_identity_state_after_publication_error();
        if matches!(&staging_state, Ok(EntryIdentityState::Expected)) {
            // The exact fragment is still at the source, so this invocation did
            // not publish it. A destination probe failure alone is not enough
            // to turn a proven pre-publication failure into a success.
            return Err(rename_error);
        }

        let error = ambiguous_publication_error(&rename_error, &destination_state, &staging_state);
        tracing::error!(%error, destination = %name, "upload publication is visible or ambiguous after rename response loss");
        Ok(self.finish_uncertain_publication(error))
    }

    fn publication_identity_state(
        &mut self,
        directory: &File,
        name: &str,
    ) -> io::Result<EntryIdentityState> {
        #[cfg(test)]
        if let Some(error) = self.take_publication_identity_probe_error() {
            return Err(error);
        }
        entry_identity_state(directory, name, self.expected_identity, EntryKind::File)
    }

    fn staging_identity_state_after_publication_error(&mut self) -> io::Result<EntryIdentityState> {
        #[cfg(test)]
        if let Some(error) = self.take_publication_identity_probe_error() {
            return Err(error);
        }
        entry_identity_state(
            &self.staging,
            &self.temporary_name,
            self.expected_identity,
            EntryKind::File,
        )
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

    fn finish_uncertain_publication(&mut self, publication_error: io::Error) -> PublishOutcome {
        // The rename may have consumed the fragment. Do not let Drop unlink or
        // otherwise reinterpret an ambiguous namespace transition as a normal
        // failed upload.
        self.published = true;
        if let Some(active_key) = self.active_key.take() {
            unregister_upload_fragment(&active_key);
        }
        match self.sync_directory() {
            Ok(()) => PublishOutcome::PublishedUncertain(publication_error),
            Err(sync_error) => PublishOutcome::PublishedUncertain(io::Error::new(
                publication_error.kind(),
                format!(
                    "{publication_error}; publication directory sync also failed: {sync_error}"
                ),
            )),
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

    #[cfg(test)]
    pub(crate) fn fail_next_publication_rename_after_success(&mut self, kind: io::ErrorKind) {
        self.next_publication_rename_error = Some(kind);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_publication_identity_probes(
        &mut self,
        kind: io::ErrorKind,
        count: usize,
    ) {
        assert!(count > 0, "identity probe failure count must be positive");
        self.next_publication_identity_probe_errors = Some((kind, count));
    }

    #[cfg(test)]
    fn inject_publication_rename_response_loss(
        &mut self,
        result: io::Result<()>,
    ) -> io::Result<()> {
        match (result, self.next_publication_rename_error.take()) {
            (Ok(()), Some(kind)) => Err(io::Error::new(
                kind,
                "injected upload rename response loss after successful publication",
            )),
            (result, _) => result,
        }
    }

    #[cfg(test)]
    fn take_publication_identity_probe_error(&mut self) -> Option<io::Error> {
        let (kind, exhausted) = {
            let (kind, remaining) = self.next_publication_identity_probe_errors.as_mut()?;
            *remaining -= 1;
            (*kind, *remaining == 0)
        };
        if exhausted {
            self.next_publication_identity_probe_errors = None;
        }
        Some(io::Error::new(
            kind,
            "injected upload publication identity probe failure",
        ))
    }
}

fn ambiguous_publication_error(
    rename_error: &io::Error,
    destination_state: &io::Result<EntryIdentityState>,
    staging_state: &io::Result<EntryIdentityState>,
) -> io::Error {
    fn describe(state: &io::Result<EntryIdentityState>) -> String {
        match state {
            Ok(EntryIdentityState::Expected) => "expected identity".to_string(),
            Ok(EntryIdentityState::Missing) => "missing".to_string(),
            Ok(EntryIdentityState::Replaced) => "different identity".to_string(),
            Err(error) => format!("probe failed: {error}"),
        }
    }

    io::Error::new(
        rename_error.kind(),
        format!(
            "upload rename outcome is ambiguous after {rename_error}; destination {}; staging {}",
            describe(destination_state),
            describe(staging_state)
        ),
    )
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
