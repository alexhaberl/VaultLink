use std::{borrow::Borrow, io};

use thiserror::Error;

use crate::{
    db::{AuditAction, AuditContext, Audited, MfaSessionProof, RequiredAuditEvent, SessionBound},
    log_safety::{EscapedLogPath, EscapedLogValue},
    path_security,
    secure_fs::{
        DeleteCommitStageOutcome, DeleteStageOutcome, EntryKind, EntryStatus,
        FileOperationRecovery, PendingDeleteCommit, RenameStageOutcome, SecureRoot,
    },
    storage_authority::{StorageMutationGuard, StorageReadGuard},
    AppState,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditDurability {
    Durable,
    Uncertain,
}

impl AuditDurability {
    pub fn is_uncertain(self) -> bool {
        self == Self::Uncertain
    }
}

#[derive(Debug, Error)]
pub enum FileOperationError {
    #[error("invalid path")]
    InvalidPath,
    #[error("invalid name")]
    InvalidName,
    #[error("entry not found")]
    NotFound,
    #[error("destination already exists")]
    Conflict,
    #[error("confirmation required")]
    ConfirmationRequired { required_name: String },
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("database executor capacity is temporarily unavailable")]
    DatabaseCapacity,
    #[error("filesystem error: {0}")]
    Io(#[source] io::Error),
    #[error("blocking task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Debug)]
pub struct CreateDirectoryResult {
    pub path: String,
    pub audit_durability: AuditDurability,
}

#[derive(Debug)]
pub struct RenameResult {
    pub path: String,
    pub kind: EntryKind,
    pub updated_shares: usize,
    pub audit_durability: AuditDurability,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenamePlan {
    pub path: String,
    pub new_name: String,
    pub destination: String,
}

#[derive(Debug)]
pub struct DeleteInspection {
    pub path: String,
    pub name: String,
    pub status: EntryStatus,
    pub affected_shares: usize,
}

#[derive(Debug)]
pub struct DeleteResult {
    pub path: String,
    pub kind: EntryKind,
    pub deactivated_shares: usize,
    pub cleanup_pending: bool,
    pub audit_durability: AuditDurability,
}

/// Internal result of a filesystem mutation that may become visible before
/// SQLite can conclusively report the required-audit commit.
///
/// Durable outcomes retain the nominal database proof. Only the explicit
/// uncertainty branch carries an unproven value; the service exposes that
/// branch separately so an adapter cannot mistake it for an audited success.
pub(crate) enum RequiredAuditFileOutcome<T> {
    Audited(SessionBound<Audited<T>>),
    Uncertain(SessionBound<T>),
}

type PreparedDeleteOutcome = (
    Option<PendingDeleteCommit>,
    String,
    EntryStatus,
    bool,
    usize,
);

fn authorized_rename_result(
    path: String,
    kind: EntryKind,
    updated_shares: usize,
    audit_durability: AuditDurability,
) -> SessionBound<RenameResult> {
    SessionBound::Authorized(RenameResult {
        path,
        kind,
        updated_shares,
        audit_durability,
    })
}

fn rename_result(
    path: String,
    kind: EntryKind,
    updated_shares: usize,
    audit_durability: AuditDurability,
) -> RenameResult {
    RenameResult {
        path,
        kind,
        updated_shares,
        audit_durability,
    }
}

fn authorized_delete_result(
    path: String,
    kind: EntryKind,
    deactivated_shares: usize,
    cleanup_pending: bool,
    audit_durability: AuditDurability,
) -> SessionBound<DeleteResult> {
    SessionBound::Authorized(DeleteResult {
        path,
        kind,
        deactivated_shares,
        cleanup_pending,
        audit_durability,
    })
}

fn delete_result(
    path: String,
    kind: EntryKind,
    deactivated_shares: usize,
    cleanup_pending: bool,
    audit_durability: AuditDurability,
) -> DeleteResult {
    DeleteResult {
        path,
        kind,
        deactivated_shares,
        cleanup_pending,
        audit_durability,
    }
}

fn validated_rename_paths(
    path: &str,
    new_name: &str,
) -> Result<(String, String), FileOperationError> {
    let plan = plan_rename(path, new_name)?;
    RequiredAuditEvent::new(
        AuditAction::PathRenamed,
        Some(plan.destination),
        Some(format!(
            "old_path={};updated_shares={};recovery=false",
            plan.path,
            usize::MAX
        )),
    )
    .validate()?;
    Ok((plan.path, plan.new_name))
}

fn finish_recovery_if_clean(
    guard: StorageMutationGuard,
    secure_root: &SecureRoot,
    database: &crate::db::Database,
    cleanup: &crate::storage_cleanup::StorageCleanupCoordinator,
    operation: &'static str,
    path: &str,
) {
    if recover_uncertain_file_operation_before_unlock(
        secure_root,
        database,
        cleanup,
        operation,
        path,
    ) {
        guard.finish_clean();
    }
}

pub(crate) async fn create_directory(
    state: &AppState,
    proof: MfaSessionProof,
    parent: &str,
    name: &str,
    audit_context: AuditContext,
) -> Result<RequiredAuditFileOutcome<CreateDirectoryResult>, FileOperationError> {
    let parent = normalize(parent, true)?;
    let name = validate_name(name)?;
    audit_context.validate()?;
    RequiredAuditEvent::new(
        AuditAction::DirectoryCreated,
        Some(if parent.is_empty() {
            name.clone()
        } else {
            format!("{parent}/{name}")
        }),
        None,
    )
    .validate()?;
    let guard = acquire_storage_mutation(state).await?;
    let secure_root = state.secure_root().clone();
    let database = state.db().clone();
    let database_permit = acquire_database_permit(&database).await?;
    let result = tokio::task::spawn_blocking(move || {
        let _database_permit = database_permit;
        let mut created_path = None;
        let result = match database.required_transaction_for_mfa_session_audited(
            &proof,
            &audit_context,
            |_transaction| {
                let (path, publication) = secure_root
                    .create_directory(&parent, &name)
                    .map_err(map_io)?;
                created_path = Some(path.clone());
                let audit_durability = match publication.uncertainty_error() {
                    Some(error) => {
                        tracing::error!(
                            error = %EscapedLogValue::new(error),
                            action = "directory_created",
                            path = %EscapedLogPath::new(&path),
                            "directory publication or parent-directory durability is uncertain"
                        );
                        AuditDurability::Uncertain
                    }
                    None => AuditDurability::Durable,
                };
                Ok::<_, FileOperationError>((
                    CreateDirectoryResult {
                        path: path.clone(),
                        audit_durability,
                    },
                    vec![RequiredAuditEvent::new(
                        AuditAction::DirectoryCreated,
                        Some(path),
                        None,
                    )],
                ))
            },
        ) {
            Ok(outcome) => Ok(RequiredAuditFileOutcome::Audited(outcome)),
            Err(FileOperationError::Database(error)) if created_path.is_some() => {
                let path = created_path.expect("created path recorded");
                tracing::error!(
                    error = %EscapedLogValue::new(&error),
                    action = "directory_created",
                    path = %EscapedLogPath::new(&path),
                    "filesystem mutation completed but required audit durability is uncertain"
                );
                Ok(RequiredAuditFileOutcome::Uncertain(
                    SessionBound::Authorized(CreateDirectoryResult {
                        path,
                        audit_durability: AuditDurability::Uncertain,
                    }),
                ))
            }
            Err(error) => Err(error),
        };
        if result.is_ok() {
            guard.finish_clean();
        }
        result
    })
    .await??;
    Ok(result)
}

pub(crate) async fn rename(
    state: &AppState,
    proof: MfaSessionProof,
    path: &str,
    new_name: &str,
    audit_context: AuditContext,
) -> Result<RequiredAuditFileOutcome<RenameResult>, FileOperationError> {
    let (path, new_name) = validated_rename_paths(path, new_name)?;
    let guard = acquire_storage_mutation(state).await?;
    let secure_root = state.secure_root().clone();
    let cleanup = state.storage_cleanup().clone();
    let database = state.db().clone();
    let database_permit = acquire_database_permit(&database).await?;
    tokio::task::spawn_blocking(move || {
        let _database_permit = database_permit;
        let mut staged_snapshot = None;
        let outcome = database.required_transaction_for_mfa_session_audited(
                &proof,
                &audit_context,
                |transaction| {
                let mut staged = match secure_root
                    .stage_rename_with_outcome(&path, &new_name)
                    .map_err(map_io)?
                {
                    RenameStageOutcome::Ready(staged) => staged,
                    RenameStageOutcome::PublishedUncertain {
                        new_path,
                        kind,
                        error,
                    } => {
                        tracing::error!(
                            error = %EscapedLogValue::new(&error),
                            action = "path_renamed",
                            path = %EscapedLogPath::new(&new_path),
                            "rename publication is visible or ambiguous; durable recovery intent was preserved"
                        );
                        return Ok::<_, FileOperationError>(((
                            None,
                            new_path,
                            kind,
                            0,
                        ), Vec::new()));
                    }
                };
                let old_path = staged.original_path().to_string();
                let new_path = staged.new_path().to_string();
                let kind = staged.kind();
                staged_snapshot = Some((new_path.clone(), kind));
                staged.begin_database_commit();
                let (updated_shares, events) = database
                    .rename_share_paths_in_transaction(
                        transaction,
                        &old_path,
                        &new_path,
                        kind == EntryKind::Directory,
                        false,
                    )
                    .map_err(FileOperationError::Database)?;
                Ok::<_, FileOperationError>(((
                    Some(staged),
                    new_path,
                    kind,
                    updated_shares,
                ), events))
                },
            );
        let audited = match outcome {
            Ok(SessionBound::Authorized(audited)) => audited,
            Ok(SessionBound::SessionUnavailable) => {
                guard.finish_clean();
                return Ok(RequiredAuditFileOutcome::Audited(
                    SessionBound::SessionUnavailable,
                ));
            }
            Err(FileOperationError::Database(error)) if staged_snapshot.is_some() => {
                let (new_path, kind) = staged_snapshot.expect("staged rename snapshot recorded");
                tracing::error!(
                    error = %EscapedLogValue::new(&error),
                    action = "path_renamed",
                    path = %EscapedLogPath::new(&new_path),
                    audit_unavailable = crate::db::is_audit_unavailable(&error),
                    "filesystem mutation completed but database/audit durability is uncertain"
                );
                finish_recovery_if_clean(
                    guard,
                    &secure_root,
                    &database,
                    &cleanup,
                    "rename",
                    &new_path,
                );
                return Ok(RequiredAuditFileOutcome::Uncertain(
                    authorized_rename_result(new_path, kind, 0, AuditDurability::Uncertain),
                ));
            }
            Err(error) => return Err(error),
        };
        let result = audited.map(|(staged, new_path, kind, updated_shares)| {
            let Some(staged) = staged else {
                finish_recovery_if_clean(
                    guard,
                    &secure_root,
                    &database,
                    &cleanup,
                    "rename",
                    &new_path,
                );
                return rename_result(new_path, kind, 0, AuditDurability::Uncertain);
            };
            if let Err(error) = staged.commit() {
                tracing::error!(
                    error = %EscapedLogValue::new(&error),
                    action = "path_renamed",
                    path = %EscapedLogPath::new(&new_path),
                    "filesystem and database mutation completed but journal finalization is uncertain"
                );
                finish_recovery_if_clean(
                    guard,
                    &secure_root,
                    &database,
                    &cleanup,
                    "rename",
                    &new_path,
                );
                return rename_result(
                    new_path,
                    kind,
                    updated_shares,
                    AuditDurability::Uncertain,
                );
            }
            guard.finish_clean();
            rename_result(
                new_path,
                kind,
                updated_shares,
                AuditDurability::Durable,
            )
        });
        Ok(RequiredAuditFileOutcome::Audited(
            SessionBound::Authorized(result),
        ))
    })
    .await?
}

fn finish_delete_outcome(
    outcome: Result<SessionBound<Audited<PreparedDeleteOutcome>>, FileOperationError>,
    committed_snapshot: Option<(String, EntryKind, bool)>,
    guard: StorageMutationGuard,
    secure_root: &SecureRoot,
    database: &crate::db::Database,
    cleanup: &crate::storage_cleanup::StorageCleanupCoordinator,
) -> Result<RequiredAuditFileOutcome<DeleteResult>, FileOperationError> {
    let audited = match outcome {
        Ok(SessionBound::Authorized(audited)) => audited,
        Ok(SessionBound::SessionUnavailable) => {
            guard.finish_clean();
            return Ok(RequiredAuditFileOutcome::Audited(
                SessionBound::SessionUnavailable,
            ));
        }
        Err(FileOperationError::Database(error)) if committed_snapshot.is_some() => {
            let (original_path, kind, cleanup_pending) =
                committed_snapshot.expect("committed delete snapshot recorded");
            tracing::error!(
                error = %EscapedLogValue::new(&error),
                action = "path_deleted",
                path = %EscapedLogPath::new(&original_path),
                audit_unavailable = crate::db::is_audit_unavailable(&error),
                "filesystem mutation completed but database/audit durability is uncertain"
            );
            if recover_uncertain_file_operation_before_unlock(
                secure_root,
                database,
                cleanup,
                "delete",
                &original_path,
            ) {
                guard.finish_clean();
            }
            return Ok(RequiredAuditFileOutcome::Uncertain(
                authorized_delete_result(
                    original_path,
                    kind,
                    0,
                    cleanup_pending,
                    AuditDurability::Uncertain,
                ),
            ));
        }
        Err(error) => return Err(error),
    };
    let result = audited.map(
        |(committed, original_path, status, cleanup_pending, deactivated_shares)| {
            let Some(committed) = committed else {
                if recover_uncertain_file_operation_before_unlock(
                    secure_root,
                    database,
                    cleanup,
                    "delete",
                    &original_path,
                ) {
                    guard.finish_clean();
                }
                return delete_result(
                    original_path,
                    status.kind,
                    0,
                    cleanup_pending,
                    AuditDurability::Uncertain,
                );
            };
            let committed = match committed.complete() {
                Ok(committed) => committed,
                Err(error) => {
                    tracing::error!(
                        error = %EscapedLogValue::new(&error),
                        action = "path_deleted",
                        path = %EscapedLogPath::new(&original_path),
                        "filesystem and database mutation completed but journal finalization is uncertain"
                    );
                    if recover_uncertain_file_operation_before_unlock(
                        secure_root,
                        database,
                        cleanup,
                        "delete",
                        &original_path,
                    ) {
                        guard.finish_clean();
                    }
                    return delete_result(
                        original_path,
                        status.kind,
                        deactivated_shares,
                        cleanup_pending,
                        AuditDurability::Uncertain,
                    );
                }
            };
            if committed.tombstone_path.is_some() {
                // Signal from the non-cancellable blocking finalizer. If the HTTP
                // future is dropped, the journal-free tombstone is still visible
                // to the process-wide worker. Requests are coalesced; the durable
                // tombstones themselves are the work list.
                cleanup.request_cleanup();
            }
            let result = delete_result(
                original_path,
                status.kind,
                deactivated_shares,
                committed.cleanup_pending,
                AuditDurability::Durable,
            );
            guard.finish_clean();
            result
        },
    );
    Ok(RequiredAuditFileOutcome::Audited(SessionBound::Authorized(
        result,
    )))
}

pub async fn inspect_delete(
    state: &AppState,
    path: &str,
) -> Result<DeleteInspection, FileOperationError> {
    let path = normalize(path, false)?;
    let name = path.rsplit('/').next().unwrap_or(&path).to_string();
    let secure_root = state.secure_root().clone();
    let database = state.db().clone();
    let inspected_path = path.clone();
    let storage_guard = acquire_storage_read(state).await?;
    let database_permit = acquire_database_permit(&database).await?;
    let (status, affected_shares) = tokio::task::spawn_blocking(move || {
        let _storage_guard = storage_guard;
        let _database_permit = database_permit;
        let status = secure_root.entry_status(&inspected_path).map_err(map_io)?;
        let affected_shares = database
            .count_active_shares_for_path(&inspected_path, status.kind == EntryKind::Directory)?;
        Ok::<_, FileOperationError>((status, affected_shares))
    })
    .await??;
    Ok(DeleteInspection {
        path,
        name,
        status,
        affected_shares,
    })
}

pub(crate) async fn delete(
    state: &AppState,
    proof: MfaSessionProof,
    path: &str,
    confirm_name: Option<&str>,
    audit_context: AuditContext,
) -> Result<RequiredAuditFileOutcome<DeleteResult>, FileOperationError> {
    let path = normalize(path, false)?;
    RequiredAuditEvent::new(AuditAction::PathDeleted, Some(path.clone()), None).validate()?;
    let confirmation = confirm_name.map(str::to_string);
    let guard = acquire_storage_mutation(state).await?;
    let secure_root = state.secure_root().clone();
    let cleanup = state.storage_cleanup().clone();
    let database = state.db().clone();
    let database_permit = acquire_database_permit(&database).await?;
    let result = tokio::task::spawn_blocking(move || {
        let _database_permit = database_permit;
        let mut committed_snapshot = None;
        let outcome = database.required_transaction_for_mfa_session_audited(
                &proof,
                &audit_context,
                |transaction| {
                let inspected = secure_root.entry_status(&path).map_err(map_io)?;
                validate_delete_confirmation(
                    &path,
                    inspected.kind == EntryKind::Directory && inspected.directory_non_empty,
                    confirmation.as_deref(),
                )?;
                let staged = match secure_root
                    .stage_delete(&path)
                    .map_err(map_io)?
                {
                    DeleteStageOutcome::Ready(staged) => *staged,
                    DeleteStageOutcome::PublishedUncertain {
                        original_path,
                        kind,
                        error,
                    } => {
                        tracing::error!(
                            error = %EscapedLogValue::new(&error),
                            action = "path_deleted",
                            path = %EscapedLogPath::new(&original_path),
                            "delete staging is visible or ambiguous; recovery metadata was preserved"
                        );
                        let status = EntryStatus {
                            kind,
                            directory_non_empty: inspected.directory_non_empty
                                && kind == EntryKind::Directory,
                        };
                        return Ok::<_, FileOperationError>(((
                            None,
                            original_path,
                            status,
                            false,
                            0,
                        ), Vec::new()));
                    }
                };
                let status = staged.status().clone();
                // A trusted external writer may change the path between inspection and
                // the atomic rename. Revalidate the staged object before touching SQLite.
                validate_delete_confirmation(
                    &path,
                    status.kind == EntryKind::Directory && status.directory_non_empty,
                    confirmation.as_deref(),
                )?;
                let original_path = staged.original_path().to_string();
                let allow_recursive = confirmation.as_deref() == original_path.rsplit('/').next();
                let committed = match staged
                    .commit_with_outcome(allow_recursive)
                    .map_err(|error| map_delete_commit_io(error, &original_path))?
                {
                    DeleteCommitStageOutcome::Ready(committed) => Some(committed),
                    DeleteCommitStageOutcome::PublishedUncertain {
                        cleanup_pending,
                        error,
                    } => {
                        tracing::error!(
                            error = %EscapedLogValue::new(&error),
                            action = "path_deleted",
                            path = %EscapedLogPath::new(&original_path),
                            "delete publication is visible or ambiguous; durable recovery metadata was preserved"
                        );
                        return Ok::<_, FileOperationError>(((
                            None,
                            original_path,
                            status,
                            cleanup_pending,
                            0,
                        ), Vec::new()));
                    }
                };
                // The durable filesystem intent now makes the SQLite update
                // recoverable. If SQLite fails (including an uncertain commit), Drop
                // deliberately leaves the intent for startup reconciliation.
                let cleanup_pending = committed
                    .as_ref()
                    .expect("ready delete commit recorded")
                    .outcome()
                    .cleanup_pending;
                committed_snapshot = Some((original_path.clone(), status.kind, cleanup_pending));
                let (deactivated_shares, events) = database
                    .deactivate_shares_for_path_in_transaction(
                        transaction,
                        &original_path,
                        status.kind == EntryKind::Directory,
                        false,
                        cleanup_pending,
                    )
                    .map_err(FileOperationError::Database)?;
                Ok::<_, FileOperationError>(((
                    committed,
                    original_path,
                    status,
                    cleanup_pending,
                    deactivated_shares,
                ), events))
                },
            );
        finish_delete_outcome(
            outcome,
            committed_snapshot,
            guard,
            &secure_root,
            &database,
            &cleanup,
        )
    })
    .await??;
    Ok(result)
}

/// Reconciles durable filesystem intents with SQLite before any route or
/// background cleanup is allowed to observe storage. The operation is
/// idempotent: on error the current journal remains and the next startup retries
/// it. Call this once immediately after `AppState::new`.
pub async fn recover_pending_file_operations(state: &AppState) -> Result<(), FileOperationError> {
    let guard = state.acquire_storage_mutation().await;
    let guard = recover_pending_file_operations_with_guard(state, guard).await?;
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
) -> Result<tokio::sync::OwnedSemaphorePermit, FileOperationError> {
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

pub fn plan_rename(path: &str, new_name: &str) -> Result<RenamePlan, FileOperationError> {
    let path = normalize(path, false)?;
    let new_name = validate_name(new_name)?;
    let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
    let destination = if parent.is_empty() {
        new_name.clone()
    } else {
        format!("{parent}/{new_name}")
    };
    if destination == path {
        return Err(FileOperationError::InvalidName);
    }
    Ok(RenamePlan {
        path,
        new_name,
        destination,
    })
}

pub fn validate_delete_confirmation(
    path: &str,
    directory_non_empty: bool,
    confirm_name: Option<&str>,
) -> Result<(), FileOperationError> {
    let path = normalize(path, false)?;
    if directory_non_empty {
        let required_name = path.rsplit('/').next().unwrap_or(&path).to_string();
        if confirm_name != Some(required_name.as_str()) {
            return Err(FileOperationError::ConfirmationRequired { required_name });
        }
    }
    Ok(())
}

pub fn kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Directory => "directory",
    }
}

fn normalize(raw: &str, allow_empty: bool) -> Result<String, FileOperationError> {
    let path =
        path_security::validate_relative(raw).map_err(|_| FileOperationError::InvalidPath)?;
    let path = path.to_string_lossy().replace('\\', "/");
    if !allow_empty && path.is_empty() {
        return Err(FileOperationError::InvalidPath);
    }
    Ok(path)
}

fn validate_name(name: &str) -> Result<String, FileOperationError> {
    path_security::safe_admin_filename(name)
        .map(str::to_string)
        .map_err(|_| FileOperationError::InvalidName)
}

fn map_io(error: io::Error) -> FileOperationError {
    match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => FileOperationError::NotFound,
        io::ErrorKind::AlreadyExists => FileOperationError::Conflict,
        io::ErrorKind::InvalidInput
        | io::ErrorKind::InvalidData
        | io::ErrorKind::PermissionDenied => FileOperationError::InvalidPath,
        _ => FileOperationError::Io(error),
    }
}

fn map_delete_commit_io(error: io::Error, original_path: &str) -> FileOperationError {
    if error.kind() == io::ErrorKind::DirectoryNotEmpty {
        return FileOperationError::ConfirmationRequired {
            required_name: original_path
                .rsplit('/')
                .next()
                .unwrap_or(original_path)
                .to_string(),
        };
    }
    map_io(error)
}

#[cfg(test)]
mod tests {
    include!("file_ops/tests/support.rs");
    include!("file_ops/tests/publication.rs");
    include!("file_ops/tests/audit_failure.rs");
    include!("file_ops/tests/cleanup.rs");
    include!("file_ops/tests/recovery.rs");
}
