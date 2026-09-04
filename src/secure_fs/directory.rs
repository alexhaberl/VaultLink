impl SecureDirectory {
    /// Compares the inode identity of two already-open directory capabilities.
    pub fn same_directory(&self, other: &Self) -> io::Result<bool> {
        let left = self.directory.metadata()?;
        let right = other.directory.metadata()?;
        Ok(left.is_dir()
            && right.is_dir()
            && (left.dev(), left.ino()) == (right.dev(), right.ino()))
    }

    /// Creates every missing directory component below this descriptor-bound
    /// scope. Existing directories are accepted, while files and symlinks fail
    /// closed when the capability is narrowed to the next component.
    pub fn ensure_directory_tree(&self, relative: &str) -> io::Result<Vec<String>> {
        let outcome = self.ensure_directory_tree_with_outcome(relative)?;
        if let Some(error) = outcome.terminal_error {
            return Err(error);
        }
        match outcome.sync_error {
            Some(error) => Err(error),
            None => Ok(outcome.created),
        }
    }

    pub(crate) fn ensure_directory_tree_with_outcome(
        &self,
        relative: &str,
    ) -> io::Result<DirectoryTreeOutcome> {
        let relative = path_security::validate_relative(relative)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid directory path"))?
            .to_string_lossy()
            .replace('\\', "/");
        let components: Vec<&str> = relative
            .split('/')
            .filter(|component| !component.is_empty())
            .collect();
        // Validate the complete user-supplied tree before the first mkdir. A
        // policy error in a later component must not turn an otherwise
        // mutation-free bad request into an unaudited partial creation.
        for component in &components {
            path_security::safe_admin_filename(component).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid directory name")
            })?;
        }
        let mut current = self.clone();
        let mut current_path = String::new();
        let mut created = Vec::new();
        let mut sync_error = None;
        for component in components {
            match current.create_directory_with_outcome(component) {
                Ok(outcome) => {
                    current_path = join_relative(&current_path, component);
                    created.push(current_path.clone());
                    if sync_error.is_none() {
                        match outcome {
                            PublishOutcome::Durable => {}
                            PublishOutcome::PublishedSyncUncertain(error)
                            | PublishOutcome::PublishedUncertain(error) => {
                                sync_error = Some(error);
                            }
                        }
                    }
                    #[cfg(test)]
                    self.run_after_directory_tree_create_hook();
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    current_path = join_relative(&current_path, component);
                }
                Err(error) => {
                    if created.is_empty() {
                        return Err(error);
                    }
                    return Ok(DirectoryTreeOutcome {
                        created,
                        sync_error,
                        terminal_error: Some(error),
                    });
                }
            }
            current = match current.bind_directory(component) {
                Ok(directory) => directory,
                Err(error) if created.is_empty() => return Err(error),
                Err(error) => {
                    return Ok(DirectoryTreeOutcome {
                        created,
                        sync_error,
                        terminal_error: Some(error),
                    });
                }
            };
        }
        Ok(DirectoryTreeOutcome {
            created,
            sync_error,
            terminal_error: None,
        })
    }

    #[cfg(test)]
    fn run_after_directory_tree_create_hook(&self) {
        let hook = self
            .after_directory_tree_create_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    fn create_directory_with_outcome(&self, name: &str) -> io::Result<PublishOutcome> {
        path_security::safe_admin_filename(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid directory name"))?;
        // A post-error probe is only meaningful after proving the name did not
        // exist before this invocation. This avoids interpreting an ordinary
        // EEXIST as a successful mkdir with a lost response.
        if entry_exists(self.directory.as_ref(), name)? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "directory already exists",
            ));
        }
        let mkdir = linux::mkdir(self.directory.as_ref(), name);
        #[cfg(test)]
        let mkdir = match (mkdir, self.take_create_directory_mkdir_error()) {
            (Ok(()), Some(kind)) => Err(io::Error::new(
                kind,
                "injected mkdir response loss after successful creation",
            )),
            (mkdir, _) => mkdir,
        };
        let publication_error = match mkdir {
            Ok(()) => None,
            Err(error) => {
                let probe = self.probe_created_directory(name);
                match probe {
                    Ok(false) => return Err(error),
                    Ok(true) => Some(io::Error::new(
                        error.kind(),
                        format!(
                            "mkdir returned an error after the directory became visible: {error}"
                        ),
                    )),
                    Err(probe_error) => Some(io::Error::new(
                        error.kind(),
                        format!(
                            "mkdir outcome is ambiguous after {error}; visibility probe failed: {probe_error}"
                        ),
                    )),
                }
            }
        };
        let sync = self.sync_created_directory_parent();
        if let Some(publication_error) = publication_error {
            return Ok(PublishOutcome::PublishedUncertain(match sync {
                Ok(()) => publication_error,
                Err(sync_error) => io::Error::new(
                    publication_error.kind(),
                    format!("{publication_error}; parent-directory sync also failed: {sync_error}"),
                ),
            }));
        }
        Ok(match sync {
            Ok(()) => PublishOutcome::Durable,
            Err(error) => PublishOutcome::PublishedSyncUncertain(error),
        })
    }

    fn probe_created_directory(&self, name: &str) -> io::Result<bool> {
        #[cfg(test)]
        if let Some(kind) = self
            .next_create_directory_probe_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            return Err(io::Error::new(
                kind,
                "injected created-directory visibility probe failure",
            ));
        }
        entry_exists(self.directory.as_ref(), name)
    }

    fn sync_created_directory_parent(&self) -> io::Result<()> {
        #[cfg(test)]
        if let Some(kind) = self
            .next_create_directory_sync_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            return Err(io::Error::new(
                kind,
                "injected directory parent sync failure",
            ));
        }
        self.directory.sync_all()
    }

    #[cfg(test)]
    fn take_create_directory_mkdir_error(&self) -> Option<io::ErrorKind> {
        self.next_create_directory_mkdir_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    fn rename_noreplace(&self, old: &str, new: &str) -> io::Result<()> {
        linux::rename_noreplace(self.directory.as_ref(), old, new)?;
        if let Err(error) = self.directory.sync_all() {
            tracing::warn!(%error, "renamed entry but parent sync was uncertain");
        }
        Ok(())
    }
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
