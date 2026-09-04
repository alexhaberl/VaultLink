impl Database {
    pub fn rotate_secrets(path: impl AsRef<Path>) -> DatabaseResult<()> {
        keyring::rotate_database(path.as_ref()).map_err(Into::into)
    }

    pub fn verify_backup(path: impl AsRef<Path>) -> DatabaseResult<()> {
        let path = path.as_ref();
        let metadata = std::fs::symlink_metadata(path).map_err(database_io_error)?;
        validate_database_metadata(path, &metadata, true)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        let opened_metadata = std::fs::symlink_metadata(path).map_err(database_io_error)?;
        validate_database_metadata(path, &opened_metadata, true)?;
        if metadata.dev() != opened_metadata.dev() || metadata.ino() != opened_metadata.ino() {
            return Err(DatabaseError::from(invalid_database_file(
                path,
                "file changed while it was opened",
            )));
        }
        schema::validate_current(&connection)?;
        let keyring = keyring::Keyring::open_read_only(path)?;
        validate_encrypted_secrets(&connection, &keyring)?;
        Ok(())
    }

    pub fn open(path: impl AsRef<Path>) -> DatabaseResult<Self> {
        Self::open_inner(path.as_ref(), None)
    }

    #[doc(hidden)]
    pub fn open_in_directory(directory: File) -> DatabaseResult<Self> {
        let metadata = directory
            .metadata()
            .map_err(database_io_error)
            .map_err(DatabaseError::from)?;
        if !metadata.is_dir() {
            return Err(DatabaseError::from(database_io_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                "validated database directory capability is not a directory",
            ))));
        }
        let effective_uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != effective_uid || metadata.mode() & 0o022 != 0 {
            return Err(DatabaseError::from(database_io_error(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "database directory capability must be service-owned and not writable by group or other users",
            ))));
        }
        let path = PathBuf::from(format!(
            "/proc/self/fd/{}/data.sqlite",
            directory.as_raw_fd()
        ));
        Self::open_inner(&path, Some(directory))
    }

    fn open_inner(path: &Path, directory_capability: Option<File>) -> DatabaseResult<Self> {
        let persistent = path != Path::new(":memory:");
        if persistent {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) => validate_database_metadata(path, &metadata, false)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(DatabaseError::from(database_io_error(error))),
            }
        }
        let flags = if persistent {
            // SQLite's NOFOLLOW mode rejects the intentional /proc/self/fd
            // magic-link used for a validated directory capability. Those
            // opens are already anchored to a service-owned directory FD and
            // receive the same pre/post final-file metadata checks below.
            if directory_capability.is_some() {
                OpenFlags::default()
            } else {
                OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW
            }
        } else {
            OpenFlags::default()
        };
        let manager = if persistent {
            SqliteConnectionManager::file(path).with_flags(flags)
        } else {
            SqliteConnectionManager::memory()
        }
        .with_init(configure_connection);
        let pool_capacity = if persistent { 4 } else { 1 };
        let pool = r2d2::Pool::builder()
            .max_size(pool_capacity)
            .connection_timeout(std::time::Duration::from_secs(1))
            .build(manager)
            .map_err(DatabaseError::Pool)?;
        let mut conn = pool.get().map_err(DatabaseError::Pool)?;
        if persistent {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(database_io_error)?;
            let metadata = std::fs::symlink_metadata(path).map_err(database_io_error)?;
            validate_database_metadata(path, &metadata, true)?;
        }
        let initialize_keyring = if persistent {
            let schema_version: i64 =
                conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
            let object_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )?;
            schema_version == 0 && object_count == 0
        } else {
            false
        };
        let keyring = if initialize_keyring {
            let keyring = keyring::Keyring::open(path, persistent, true)?;
            schema::migrate(&mut conn)?;
            keyring
        } else {
            // Existing databases are schema-validated before consulting the
            // keyring so operators receive the fail-closed schema diagnosis
            // for legacy or unexpected layouts even when no keyring exists.
            schema::migrate(&mut conn)?;
            keyring::Keyring::open(path, persistent, false)?
        };
        validate_encrypted_secrets(&conn, &keyring)?;
        drop(conn);
        Ok(Self(Arc::new(DatabaseInner {
            pool,
            runtime_admission: Arc::new(tokio::sync::Semaphore::new(pool_capacity as usize)),
            audit_retention_admission: Mutex::new(()),
            transfer_write_admission: Mutex::new(()),
            keyring,
            session_idle_minutes: AtomicI64::new(30),
            _directory_capability: directory_capability,
        })))
    }

    fn encrypt_secret(&self, plaintext: &[u8], aad: &[u8]) -> rusqlite::Result<(u64, Vec<u8>)> {
        self.0.keyring.encrypt(plaintext, aad)
    }

    fn decrypt_secret(
        &self,
        key_id: u64,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> rusqlite::Result<Vec<u8>> {
        self.0.keyring.decrypt(key_id, ciphertext, aad)
    }

    /// Returns the fair runtime-side admission queue shared by all clones.
    /// The semaphore is never closed during normal operation; callers retain
    /// the owned permit inside their blocking task so request cancellation
    /// cannot release capacity before SQLite work actually ends.
    #[doc(hidden)]
    pub async fn acquire_runtime_permit(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::AcquireError> {
        self.0.runtime_admission.clone().acquire_owned().await
    }

    /// Synchronous fast path for RAII finalizers that must enqueue their
    /// blocking cleanup before a short-lived Tokio runtime can shut down.
    /// Saturated callers retain the normal fair asynchronous fallback.
    pub(crate) fn try_acquire_runtime_permit(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.0.runtime_admission.clone().try_acquire_owned()
    }

    /// Releases a session-bound value only through the database-owned
    /// required-audit boundary. Callers must already be running inside the
    /// admitted blocking database task; the closure cannot return an
    /// unaudited value by construction.
    pub(crate) fn run_required_session_audit<T, E, F>(
        &self,
        operation: F,
    ) -> Result<SessionBound<T>, E>
    where
        F: FnOnce(&Database) -> Result<SessionBound<Audited<T>>, E>,
    {
        required_audit::run_session_audited(self, operation)
    }

    #[cfg(test)]
    pub(crate) fn runtime_available_permits(&self) -> usize {
        self.0.runtime_admission.available_permits()
    }

    #[cfg(test)]
    pub(crate) fn required_audit_failure_for_test<T>(
        &self,
        error: rusqlite::Error,
    ) -> rusqlite::Result<Audited<T>> {
        Err(error)
    }
}

fn configure_connection(connection: &mut Connection) -> rusqlite::Result<()> {
    // r2d2 opens pool members concurrently. Install the busy handler before
    // each connection negotiates WAL mode so simultaneous first opens wait
    // for the schema/journal writer instead of failing immediately with
    // SQLITE_BUSY on slower architectures.
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.set_prepared_statement_cache_capacity(128);
    Ok(())
}

fn pool_error(error: &r2d2::Error) -> rusqlite::Error {
    database_io_error(io::Error::other(format!(
        "database connection pool unavailable: {error}"
    )))
}

fn validate_encrypted_secrets(
    connection: &Connection,
    keyring: &keyring::Keyring,
) -> rusqlite::Result<()> {
    {
        let mut statement =
            connection.prepare("SELECT token_hash,token_key_id,token_ciphertext FROM shares")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get(1)?, row.get(2)?))
        })?;
        for row in rows {
            let (stable_id, key_id, ciphertext): (String, u64, Vec<u8>) = row?;
            let aad = format!("shares.token:{stable_id}");
            let _plaintext =
                zeroize::Zeroizing::new(keyring.decrypt(key_id, &ciphertext, aad.as_bytes())?);
        }
    }
    {
        let mut statement =
            connection.prepare("SELECT username,totp_key_id,totp_ciphertext FROM admins")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get(1)?, row.get(2)?))
        })?;
        for row in rows {
            let (username, key_id, ciphertext): (String, u64, Vec<u8>) = row?;
            let aad = format!("admins.totp:{}", username.to_lowercase());
            let _plaintext =
                zeroize::Zeroizing::new(keyring.decrypt(key_id, &ciphertext, aad.as_bytes())?);
        }
    }
    {
        let mut statement = connection
            .prepare("SELECT token_hash,totp_key_id,totp_ciphertext FROM admin_mfa_enrollments")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get(1)?, row.get(2)?))
        })?;
        for row in rows {
            let (stable_id, key_id, ciphertext): (String, u64, Vec<u8>) = row?;
            let aad = format!("admin_mfa_enrollments.totp:{stable_id}");
            let _plaintext =
                zeroize::Zeroizing::new(keyring.decrypt(key_id, &ciphertext, aad.as_bytes())?);
        }
    }
    Ok(())
}

fn database_io_error(error: io::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

fn invalid_database_file(path: &Path, reason: &str) -> rusqlite::Error {
    database_io_error(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unsafe database file {}: {reason}", path.display()),
    ))
}

fn validate_database_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    require_private_mode: bool,
) -> rusqlite::Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(invalid_database_file(
            path,
            "symbolic links are not allowed",
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(invalid_database_file(path, "path is not a regular file"));
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(invalid_database_file(
            path,
            "file is not owned by the effective service user",
        ));
    }
    if metadata.nlink() != 1 {
        return Err(invalid_database_file(path, "hard links are not allowed"));
    }
    if require_private_mode && metadata.mode() & 0o7777 != 0o600 {
        return Err(invalid_database_file(path, "file mode is not 0600"));
    }
    Ok(())
}

impl Database {
    pub(crate) fn configure_session_idle_timeout(&self, minutes: i64) {
        self.0
            .session_idle_minutes
            .store(minutes, Ordering::Relaxed);
    }

    fn session_idle_minutes(&self) -> i64 {
        self.0.session_idle_minutes.load(Ordering::Relaxed)
    }

    pub(crate) fn readiness_check(&self) -> Result<(), String> {
        let connection = self
            .0
            .pool
            .try_get()
            .ok_or_else(|| "database connection pool is exhausted".to_string())?;
        let value = connection
            .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
            .map_err(|error| error.to_string())?;
        if value != 1 {
            return Err("database readiness query returned an invalid value".into());
        }
        Ok(())
    }

    fn try_conn(&self) -> rusqlite::Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        self.0.pool.get().map_err(|error| pool_error(&error))
    }

    fn transfer_write_guard(&self) -> rusqlite::Result<MutexGuard<'_, ()>> {
        self.0.transfer_write_admission.lock().map_err(|_| {
            database_io_error(io::Error::other(
                "transfer database writer admission is poisoned",
            ))
        })
    }

    fn audit_retention_guard(&self) -> rusqlite::Result<MutexGuard<'_, ()>> {
        self.0.audit_retention_admission.lock().map_err(|_| {
            database_io_error(io::Error::other(
                "audit retention database admission is poisoned",
            ))
        })
    }

    #[cfg(test)]
    fn conn(&self) -> r2d2::PooledConnection<SqliteConnectionManager> {
        self.try_conn().expect("database connection unavailable")
    }

    pub(crate) fn required_transaction<T, F>(
        &self,
        context: &AuditContext,
        operation: F,
    ) -> rusqlite::Result<T>
    where
        F: FnOnce(&rusqlite::Transaction<'_>) -> rusqlite::Result<(T, Vec<RequiredAuditEvent>)>,
    {
        self.required_transaction_audited(context, operation)
            .map(Audited::into_legacy_inner)
    }

    pub(crate) fn required_transaction_audited<T, F>(
        &self,
        context: &AuditContext,
        operation: F,
    ) -> rusqlite::Result<Audited<T>>
    where
        F: FnOnce(&rusqlite::Transaction<'_>) -> rusqlite::Result<(T, Vec<RequiredAuditEvent>)>,
    {
        let mut connection = self.try_conn()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (outcome, events) = operation(&transaction)?;
        insert_required_audits(&transaction, context, &events)?;
        transaction.commit()?;
        trace_required_audits(context, &events);
        Ok(Audited::new(outcome))
    }
}
