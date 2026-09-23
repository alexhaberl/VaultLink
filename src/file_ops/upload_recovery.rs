/// Reconciles durable filesystem intents with SQLite before any route or
/// background cleanup is allowed to observe storage. The operation is
/// idempotent: on error the current journal remains and the next startup retries
/// it. Call this once immediately after `AppState::new`.
pub async fn recover_pending_file_operations(state: &AppState) -> Result<(), FileOperationError> {
    let guard = state.acquire_storage_mutation().await;
    let guard = recover_pending_file_operations_with_guard(state, guard).await?;
    state
        .db()
        .recover_upload_operations()
        .map_err(FileOperationError::Database)?;
    guard.finish_clean();
    Ok(())
}

pub(crate) async fn recover_pending_file_operations_with_guard(
    state: &AppState,
    guard: StorageMutationGuard,
) -> Result<StorageMutationGuard, FileOperationError> {
    if !guard.recovery_required_on_entry() {
        return Ok(guard);
    }
    let secure_root = state.secure_root().clone();
    let database = state.db().clone();
    let cleanup = state.storage_cleanup().clone();
    let database_permit = acquire_database_permit(&database).await?;
    let guard = tokio::task::spawn_blocking(move || {
        let _database_permit = database_permit;
        // spawn_blocking tasks continue after their awaiting request is
        // cancelled. Owning the guard here keeps recovery serialized until the
        // task has actually finished.
        let cleanup_paths = recover_pending_file_operations_blocking(&secure_root, &database)?;
        database
            .recover_upload_operations()
            .map_err(FileOperationError::Database)?;
        if !cleanup_paths.is_empty() {
            // Signal before returning the guard/result: spawn_blocking keeps
            // running after request cancellation, while code after `.await`
            // would be skipped with its result discarded.
            cleanup.request_cleanup();
        }
        Ok::<_, FileOperationError>(guard)
    })
    .await??;
    Ok(guard)
}

/// Acquires exclusive namespace authority, first coalescing any recovery left
/// by a cancelled or failed writer. The returned guard is already marked dirty
/// and must be moved into the operation's non-cancellable finalizer.
pub(crate) async fn acquire_storage_mutation(
    state: &(impl Borrow<AppState> + ?Sized),
) -> Result<StorageMutationGuard, FileOperationError> {
    let state = state.borrow();
    let guard = state.acquire_storage_mutation().await;
    recover_pending_file_operations_with_guard(state, guard).await
}

/// Returns a clean, parallel storage view. Dirty readers converge on the fair
/// writer queue; only the first writer that still observes the sticky flag runs
/// recovery, while all later readers reuse the resulting generation.
pub(crate) async fn acquire_storage_read(
    state: &(impl Borrow<AppState> + ?Sized),
) -> Result<StorageReadGuard, FileOperationError> {
    let state = state.borrow();
    loop {
        let read = state.acquire_storage_read().await;
        if !state.storage_recovery_required() {
            tracing::trace!(
                storage_generation = read.generation(),
                "clean storage read admitted"
            );
            return Ok(read);
        }
        drop(read);

        let recovery = state.acquire_storage_recovery().await;
        if !recovery.recovery_required_on_entry() {
            drop(recovery);
            continue;
        }
        let recovery = recover_pending_file_operations_with_guard(state, recovery).await?;
        recovery.finish_clean();
    }
}

pub(crate) async fn acquire_database_permit(
    database: &crate::db::Database,
) -> Result<crate::db::RuntimeDatabasePermit, FileOperationError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        database.acquire_runtime_permit(),
    )
    .await
    .map_err(|_| FileOperationError::DatabaseCapacity)?
    .map_err(|_| FileOperationError::DatabaseCapacity)
}

fn recover_pending_file_operations_blocking(
    secure_root: &SecureRoot,
    database: &crate::db::Database,
) -> Result<Vec<String>, FileOperationError> {
    let mut cleanup_paths = Vec::new();
    let pending_operations = secure_root.pending_file_operations().map_err(map_io)?;
    // A delete can lose the rename response before its durable operation
    // journal is promoted. Its pending manifest is already sufficient to
    // restore the visible name, and must be reconciled while the caller still
    // owns the storage lock.
    secure_root
        .recover_pending_deletions(&pending_operations)
        .map_err(map_io)?;
    for pending in pending_operations {
        match secure_root
            .recover_file_operation(&pending)
            .map_err(map_io)?
        {
            FileOperationRecovery::Rename {
                original_path,
                new_path,
                is_directory,
            } => {
                database.rename_share_paths_and_audit(
                    &original_path,
                    &new_path,
                    is_directory,
                    &AuditContext::system(),
                    true,
                )?;
                secure_root
                    .complete_file_operation(&pending)
                    .map_err(map_io)?;
                tracing::warn!(
                    from = %EscapedLogPath::new(&original_path),
                    to = %EscapedLogPath::new(&new_path),
                    "completed interrupted rename operation"
                );
            }
            FileOperationRecovery::Delete {
                original_path,
                is_directory,
                tombstone_path,
            } => {
                database.deactivate_shares_for_path_and_audit(
                    &original_path,
                    is_directory,
                    &AuditContext::system(),
                    true,
                    tombstone_path.is_some(),
                )?;
                secure_root
                    .complete_file_operation(&pending)
                    .map_err(map_io)?;
                if let Some(tombstone_path) = tombstone_path {
                    cleanup_paths.push(tombstone_path);
                }
                tracing::warn!(
                    path = %EscapedLogPath::new(&original_path),
                    "completed interrupted delete operation"
                );
            }
            FileOperationRecovery::Cancelled => {
                tracing::warn!(
                    "cancelled an interrupted filesystem operation without changing SQLite"
                );
            }
        }
    }
    Ok(cleanup_paths)
}

/// Makes one reconciliation attempt while the caller still owns the storage
/// mutation lock. The writer transaction that produced the uncertain outcome
/// must already be closed: recovery deliberately opens its own SQLite
/// transaction. A failed attempt is logged but does not replace the operation's
/// `Authorized/uncertain` result; the durable journal remains for startup or the
/// next mutation to retry.
fn recover_uncertain_file_operation_before_unlock(
    secure_root: &SecureRoot,
    database: &crate::db::Database,
    cleanup: &crate::storage_cleanup::StorageCleanupCoordinator,
    operation: &'static str,
    path: &str,
) -> bool {
    match recover_pending_file_operations_blocking(secure_root, database) {
        Ok(cleanup_paths) => {
            if !cleanup_paths.is_empty() {
                cleanup.request_cleanup();
            }
            true
        }
        Err(error) => {
            tracing::error!(
                error = %EscapedLogValue::new(&error),
                operation,
                path = %EscapedLogPath::new(path),
                "immediate filesystem-operation recovery failed; durable journal was preserved"
            );
            false
        }
    }
}
