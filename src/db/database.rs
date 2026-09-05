const TRANSFER_CLEANUP_QUEUE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

struct TransferCleanupThreadWake(std::thread::Thread);

impl std::task::Wake for TransferCleanupThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

struct TransferCleanupWorkerLaunchGuard {
    database: Database,
    armed: bool,
}

impl TransferCleanupWorkerLaunchGuard {
    fn new(database: Database) -> Self {
        Self {
            database,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TransferCleanupWorkerLaunchGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut queue = self.database.transfer_cleanup_queue_guard();
        queue.jobs.clear();
        queue.worker_active = false;
    }
}

impl TransferCleanupKind {
    fn class(&self) -> &'static str {
        match self {
            Self::UploadReservation(_) => "upload_reservation_cancel",
            Self::TransferLease(_) => "transfer_cancel",
        }
    }

    fn run(self, database: &Database) -> rusqlite::Result<()> {
        match self {
            Self::UploadReservation(token) => {
                database.cancel_upload_reservation(&token).map(|_| ())
            }
            Self::TransferLease(token) => database.cancel_transfer_lease(&token).map(|_| ()),
        }
    }
}

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
            .build_unchecked(manager);
        // Startup must tolerate SQLite's five-second busy handler and pool
        // worker scheduling without extending the runtime checkout budget.
        warm_connection_pool(&pool, std::time::Duration::from_secs(10))
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
            transfer_runtime_admission: Arc::new(tokio::sync::Semaphore::new(1)),
            audit_retention_admission: Mutex::new(()),
            transfer_write_admission: Mutex::new(()),
            transfer_cleanup_queue: Mutex::new(TransferCleanupQueue::default()),
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

    /// Admits one runtime transfer writer before it enters the fair general
    /// database queue. Callers apply one timeout around this whole acquisition
    /// so the transfer and database queues share the existing one-second
    /// overload budget.
    pub(crate) async fn acquire_transfer_runtime_permit(
        &self,
    ) -> Result<TransferDatabasePermit, tokio::sync::AcquireError> {
        let transfer = self
            .0
            .transfer_runtime_admission
            .clone()
            .acquire_owned()
            .await?;
        let runtime = self.0.runtime_admission.clone().acquire_owned().await?;
        Ok(TransferDatabasePermit {
            _transfer: transfer,
            _runtime: runtime,
        })
    }

    pub(crate) fn enqueue_upload_reservation_cleanup(
        &self,
        handle: &tokio::runtime::Handle,
        token: String,
    ) {
        self.enqueue_transfer_cleanup(handle, TransferCleanupKind::UploadReservation(token));
    }

    pub(crate) fn enqueue_transfer_lease_cleanup(
        &self,
        handle: &tokio::runtime::Handle,
        token: String,
    ) {
        self.enqueue_transfer_cleanup(handle, TransferCleanupKind::TransferLease(token));
    }

    fn enqueue_transfer_cleanup(&self, handle: &tokio::runtime::Handle, kind: TransferCleanupKind) {
        let deadline = std::time::Instant::now() + TRANSFER_CLEANUP_QUEUE_TIMEOUT;
        let start_worker = {
            let mut queue = self.transfer_cleanup_queue_guard();
            queue.jobs.push_back(TransferCleanupJob { deadline, kind });
            if queue.worker_active {
                false
            } else {
                queue.worker_active = true;
                true
            }
        };
        if start_worker {
            let database = self.clone();
            let launch_guard = TransferCleanupWorkerLaunchGuard::new(self.clone());
            // Drop cannot await admission, and the runtime may shut down as
            // soon as Drop returns. Schedule exactly one bounded drain worker
            // synchronously; it performs no database work and holds no global
            // permit until the ordered composite admission below succeeds.
            // If Tokio discards the queued closure during shutdown, its armed
            // launch guard restores the idle state and drops the unadmitted
            // jobs instead of leaving future cleanups behind a phantom worker.
            drop(handle.spawn_blocking(move || {
                let mut launch_guard = launch_guard;
                launch_guard.disarm();
                database.drain_transfer_cleanup_queue();
            }));
        }
    }

    fn drain_transfer_cleanup_queue(&self) {
        loop {
            let job = {
                let mut queue = self.transfer_cleanup_queue_guard();
                let Some(job) = queue.jobs.pop_front() else {
                    queue.worker_active = false;
                    return;
                };
                job
            };
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.run_transfer_cleanup_job(job);
            }))
            .is_err()
            {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    tracing::error!(
                        operation = "database.transfer_cleanup.panic",
                        "transfer database cleanup worker panicked"
                    );
                }));
            }
        }
    }

    fn run_transfer_cleanup_job(&self, job: TransferCleanupJob) {
        let class = job.kind.class();
        let Some(permit) = blocking_acquire_transfer_runtime_permit(self, job.deadline) else {
            tracing::trace!(
                operation = "database.transfer_cleanup",
                class,
                "transfer database cleanup admission expired"
            );
            return;
        };
        let result = job.kind.run(self);
        drop(permit);
        if result.is_err() {
            tracing::warn!(
                operation = "database.transfer_cleanup",
                class,
                "transfer database cleanup failed"
            );
        } else {
            tracing::trace!(
                operation = "database.transfer_cleanup",
                class,
                "transfer database cleanup finished"
            );
        }
    }

    fn transfer_cleanup_queue_guard(&self) -> MutexGuard<'_, TransferCleanupQueue> {
        self.0
            .transfer_cleanup_queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
    pub(crate) fn transfer_cleanup_queue_state_for_test(&self) -> (bool, usize) {
        let queue = self.transfer_cleanup_queue_guard();
        (queue.worker_active, queue.jobs.len())
    }

    #[cfg(test)]
    pub(crate) fn required_audit_failure_for_test<T>(
        &self,
        error: rusqlite::Error,
    ) -> rusqlite::Result<Audited<T>> {
        Err(error)
    }
}

/// Polls the semaphore-only composite admission future from the single cleanup
/// worker. A thread-backed waker makes this independent of Tokio's timer and
/// I/O drivers, which may already be shutting down, without busy-spinning.
fn blocking_acquire_transfer_runtime_permit(
    database: &Database,
    deadline: std::time::Instant,
) -> Option<TransferDatabasePermit> {
    let waker = std::task::Waker::from(Arc::new(TransferCleanupThreadWake(std::thread::current())));
    let mut context = std::task::Context::from_waker(&waker);
    let mut acquisition = std::pin::pin!(database.acquire_transfer_runtime_permit());
    loop {
        let remaining = deadline.checked_duration_since(std::time::Instant::now())?;
        match std::future::Future::poll(acquisition.as_mut(), &mut context) {
            std::task::Poll::Ready(Ok(permit)) => return Some(permit),
            std::task::Poll::Ready(Err(_)) => return None,
            std::task::Poll::Pending => std::thread::park_timeout(remaining),
        }
    }
}

fn warm_connection_pool(
    pool: &r2d2::Pool<SqliteConnectionManager>,
    timeout: std::time::Duration,
) -> Result<(), r2d2::Error> {
    let deadline = std::time::Instant::now() + timeout;
    // Retain every checkout until the entire pool is ready. Returning each
    // connection immediately would repeatedly check out the same member and
    // let startup succeed with only part of the pool initialized.
    let mut connections = Vec::with_capacity(pool.max_size() as usize);
    for _ in 0..pool.max_size() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        connections.push(pool.get_timeout(remaining)?);
    }
    Ok(())
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
        context.validate()?;
        let (outcome, events) = operation(&transaction)?;
        insert_required_audits(&transaction, context, &events)?;
        transaction.commit()?;
        trace_required_audits(context, &events);
        Ok(Audited::new(outcome))
    }
}
