use std::io;

use thiserror::Error;

use crate::{
    db::AuditContext,
    path_security,
    secure_fs::{EntryKind, EntryStatus, FileOperationRecovery, SecureRoot},
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

pub async fn create_directory(
    state: &AppState,
    parent: &str,
    name: &str,
    audit_context: AuditContext,
) -> Result<CreateDirectoryResult, FileOperationError> {
    let parent = normalize(parent, true)?;
    let name = validate_name(name)?;
    let guard = state.storage_mutation.clone().lock_owned().await;
    let guard = recover_pending_file_operations_with_guard(state, guard).await?;
    let secure_root = state.secure_root.clone();
    let database = state.db.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _storage_guard = guard;
        let path = secure_root
            .create_directory(&parent, &name)
            .map_err(map_io)?;
        let audit_durability = match database.audit_with_client_ip(
            &audit_context.actor,
            "directory_created",
            Some(&path),
            None,
            audit_context.client_ip.as_deref(),
        ) {
            Ok(()) => AuditDurability::Durable,
            Err(error) => {
                tracing::error!(
                    %error,
                    action = "directory_created",
                    path,
                    "filesystem mutation completed but required audit durability is uncertain"
                );
                AuditDurability::Uncertain
            }
        };
        Ok::<_, FileOperationError>(CreateDirectoryResult {
            path,
            audit_durability,
        })
    })
    .await??;
    Ok(result)
}

pub async fn rename(
    state: &AppState,
    path: &str,
    new_name: &str,
    audit_context: AuditContext,
) -> Result<RenameResult, FileOperationError> {
    let plan = plan_rename(path, new_name)?;
    let path = plan.path;
    let new_name = plan.new_name;
    let guard = state.storage_mutation.clone().lock_owned().await;
    let guard = recover_pending_file_operations_with_guard(state, guard).await?;
    let secure_root = state.secure_root.clone();
    let database = state.db.clone();
    tokio::task::spawn_blocking(move || {
        let _storage_guard = guard;
        let mut staged = secure_root.stage_rename(&path, &new_name).map_err(map_io)?;
        let old_path = staged.original_path().to_string();
        let new_path = staged.new_path().to_string();
        let kind = staged.kind();
        staged.begin_database_commit();
        let updated_shares = match database.rename_share_paths_and_audit(
            &old_path,
            &new_path,
            kind == EntryKind::Directory,
            &audit_context,
            false,
        ) {
            Ok(updated_shares) => updated_shares,
            Err(error) => {
                tracing::error!(
                    %error,
                    action = "path_renamed",
                    path = new_path,
                    audit_unavailable = crate::db::is_audit_unavailable(&error),
                    "filesystem mutation completed but database/audit durability is uncertain"
                );
                return Ok(RenameResult {
                    path: new_path,
                    kind,
                    updated_shares: 0,
                    audit_durability: AuditDurability::Uncertain,
                });
            }
        };
        if let Err(error) = staged.commit() {
            tracing::error!(
                %error,
                action = "path_renamed",
                path = new_path,
                "filesystem and database mutation completed but journal finalization is uncertain"
            );
            return Ok(RenameResult {
                path: new_path,
                kind,
                updated_shares,
                audit_durability: AuditDurability::Uncertain,
            });
        }
        Ok(RenameResult {
            path: new_path,
            kind,
            updated_shares,
            audit_durability: AuditDurability::Durable,
        })
    })
    .await?
}

pub async fn inspect_delete(
    state: &AppState,
    path: &str,
) -> Result<DeleteInspection, FileOperationError> {
    let path = normalize(path, false)?;
    let name = path.rsplit('/').next().unwrap_or(&path).to_string();
    let secure_root = state.secure_root.clone();
    let database = state.db.clone();
    let inspected_path = path.clone();
    let (status, affected_shares) = tokio::task::spawn_blocking(move || {
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

pub async fn delete(
    state: &AppState,
    path: &str,
    confirm_name: Option<&str>,
    audit_context: AuditContext,
) -> Result<DeleteResult, FileOperationError> {
    let path = normalize(path, false)?;
    let confirmation = confirm_name.map(str::to_string);
    let guard = state.storage_mutation.clone().lock_owned().await;
    let guard = recover_pending_file_operations_with_guard(state, guard).await?;
    let secure_root = state.secure_root.clone();
    let cleanup = state.storage_cleanup.clone();
    let database = state.db.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _storage_guard = guard;
        let inspected = secure_root.entry_status(&path).map_err(map_io)?;
        validate_delete_confirmation(
            &path,
            inspected.kind == EntryKind::Directory && inspected.directory_non_empty,
            confirmation.as_deref(),
        )?;
        let staged = secure_root.stage_delete(&path).map_err(map_io)?;
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
        let committed = staged
            .commit(allow_recursive)
            .map_err(|error| map_delete_commit_io(error, &original_path))?;
        // The durable filesystem intent now makes this SQLite update
        // recoverable. If SQLite fails (including an uncertain commit), Drop
        // deliberately leaves the intent for startup reconciliation.
        let cleanup_pending = committed.outcome().cleanup_pending;
        let deactivated_shares = match database.deactivate_shares_for_path_and_audit(
            &original_path,
            status.kind == EntryKind::Directory,
            &audit_context,
            false,
            cleanup_pending,
        ) {
            Ok(deactivated_shares) => deactivated_shares,
            Err(error) => {
                tracing::error!(
                    %error,
                    action = "path_deleted",
                    path = original_path,
                    audit_unavailable = crate::db::is_audit_unavailable(&error),
                    "filesystem mutation completed but database/audit durability is uncertain"
                );
                drop(committed);
                return Ok(DeleteResult {
                    path: original_path,
                    kind: status.kind,
                    deactivated_shares: 0,
                    cleanup_pending,
                    audit_durability: AuditDurability::Uncertain,
                });
            }
        };
        let committed = match committed.complete() {
            Ok(committed) => committed,
            Err(error) => {
                tracing::error!(
                    %error,
                    action = "path_deleted",
                    path = original_path,
                    "filesystem and database mutation completed but journal finalization is uncertain"
                );
                return Ok(DeleteResult {
                    path: original_path,
                    kind: status.kind,
                    deactivated_shares,
                    cleanup_pending,
                    audit_durability: AuditDurability::Uncertain,
                });
            }
        };
        if committed.tombstone_path.is_some() {
            // Signal from the non-cancellable blocking finalizer. If the HTTP
            // future is dropped, the journal-free tombstone is still visible
            // to the process-wide worker. Requests are coalesced; the durable
            // tombstones themselves are the work list.
            cleanup.request_cleanup();
        }
        Ok::<_, FileOperationError>(DeleteResult {
            path: original_path,
            kind: status.kind,
            deactivated_shares,
            cleanup_pending: committed.cleanup_pending,
            audit_durability: AuditDurability::Durable,
        })
    })
    .await??;
    Ok(result)
}

/// Reconciles durable filesystem intents with SQLite before any route or
/// background cleanup is allowed to observe storage. The operation is
/// idempotent: on error the current journal remains and the next startup retries
/// it. Call this once immediately after `AppState::new`.
pub async fn recover_pending_file_operations(state: &AppState) -> Result<(), FileOperationError> {
    let guard = state.storage_mutation.clone().lock_owned().await;
    recover_pending_file_operations_with_guard(state, guard)
        .await
        .map(drop)
}

pub(crate) async fn recover_pending_file_operations_with_guard(
    state: &AppState,
    guard: tokio::sync::OwnedMutexGuard<()>,
) -> Result<tokio::sync::OwnedMutexGuard<()>, FileOperationError> {
    let secure_root = state.secure_root.clone();
    let database = state.db.clone();
    let cleanup = state.storage_cleanup.clone();
    let guard = tokio::task::spawn_blocking(move || {
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

fn recover_pending_file_operations_blocking(
    secure_root: &SecureRoot,
    database: &crate::db::Database,
) -> Result<Vec<String>, FileOperationError> {
    let mut cleanup_paths = Vec::new();
    for pending in secure_root.pending_file_operations().map_err(map_io)? {
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
                tracing::warn!(from = %original_path, to = %new_path, "completed interrupted rename operation");
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
                tracing::warn!(path = %original_path, "completed interrupted delete operation");
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
    use std::path::{Path, PathBuf};

    use crate::{
        config::{Config, Logging, ReverseProxy, Security, Server, ServerMode, Storage, Tls},
        db::{Permission, UploadConflictStrategy},
    };

    use super::*;

    fn test_state(root: &Path, data: &Path) -> AppState {
        AppState::new(Config {
            server: Server {
                mode: ServerMode::Development,
                listen_address: "127.0.0.1:8080".into(),
                public_base_url: "http://localhost:8080".into(),
                production_mode: false,
            },
            storage: Storage {
                root_mount_path: root.into(),
                data_directory: data.into(),
                internal_directory: Some(root.join(crate::config::DEFAULT_INTERNAL_DIRECTORY_NAME)),
                require_mount: false,
                external_writers: false,
                allow_external_writer_replace: false,
                expected_filesystem_type: None,
                expected_mount_source: None,
                max_upload_size: 1_000_000,
                max_zip_size: 1_000_000,
                max_zip_files: 100,
                max_search_entries: 1_000,
                max_search_results: 100,
                max_preview_size: 100_000,
                preview_extensions: vec!["txt".into()],
                image_preview_extensions: vec!["png".into()],
                pdf_preview_enabled: true,
                max_media_preview_size: 1_000_000,
                blocked_extensions: vec!["exe".into()],
            },
            reverse_proxy: ReverseProxy::default(),
            tls: Tls::default(),
            security: Security::default(),
            logging: Logging::default(),
        })
        .unwrap()
    }

    fn tombstone_paths(root: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(
            root.join(crate::path_security::INTERNAL_STORAGE_DIRECTORY_NAME)
                .join("tombstones"),
        )
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| crate::secure_fs::is_deletion_tombstone_name(&entry.file_name()))
        .map(|entry| entry.path())
        .collect()
    }

    fn install_audit_failure(data: &Path) -> rusqlite::Connection {
        let connection = rusqlite::Connection::open(data.join("data.sqlite")).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER fail_required_audit
                 BEFORE INSERT ON audit
                 BEGIN SELECT RAISE(FAIL, 'injected audit failure'); END;",
            )
            .unwrap();
        connection
    }

    fn install_share_update_failure(data: &Path) -> rusqlite::Connection {
        let connection = rusqlite::Connection::open(data.join("data.sqlite")).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER fail_share_update
                 BEFORE UPDATE ON shares
                 BEGIN SELECT RAISE(FAIL, 'injected share update failure'); END;",
            )
            .unwrap();
        connection
    }

    #[tokio::test]
    async fn published_directory_reports_audit_durability_uncertain_without_retrying() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let fault = install_audit_failure(data.path());

        let result = create_directory(&state, "", "created", AuditContext::new("admin", None))
            .await
            .unwrap();
        assert_eq!(result.audit_durability, AuditDurability::Uncertain);
        assert!(root.path().join("created").is_dir());
        assert_eq!(state.db.count_audit(None).unwrap(), 0);

        fault
            .execute_batch("DROP TRIGGER fail_required_audit;")
            .unwrap();
        assert_eq!(state.db.count_audit(None).unwrap(), 0);
    }

    #[tokio::test]
    async fn rename_audit_failure_is_uncertain_and_recovery_finishes_once_as_system() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("old.txt"), b"content").unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_share(
                "rename-audit-token",
                None,
                "old.txt",
                false,
                &Permission::DownloadOnly,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let fault = install_audit_failure(data.path());

        let result = rename(
            &state,
            "old.txt",
            "new.txt",
            AuditContext::new("admin", None),
        )
        .await
        .unwrap();
        assert_eq!(result.audit_durability, AuditDurability::Uncertain);
        assert!(root.path().join("new.txt").is_file());
        assert_eq!(
            state
                .db
                .share_by_token("rename-audit-token")
                .unwrap()
                .unwrap()
                .relative_path,
            "old.txt"
        );
        assert_eq!(
            state.secure_root.pending_file_operations().unwrap().len(),
            1
        );

        fault
            .execute_batch("DROP TRIGGER fail_required_audit;")
            .unwrap();
        recover_pending_file_operations(&state).await.unwrap();
        recover_pending_file_operations(&state).await.unwrap();
        assert_eq!(
            state
                .db
                .share_by_token("rename-audit-token")
                .unwrap()
                .unwrap()
                .relative_path,
            "new.txt"
        );
        let events = state.db.list_audit(Some("path_renamed"), 10, 0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, "system");
        assert!(events[0].client_ip.is_none());
    }

    #[tokio::test]
    async fn delete_audit_failure_is_uncertain_and_recovery_finishes_once_as_system() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("remove.txt"), b"content").unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_share(
                "delete-audit-token",
                None,
                "remove.txt",
                false,
                &Permission::DownloadOnly,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let fault = install_audit_failure(data.path());

        let result = delete(&state, "remove.txt", None, AuditContext::new("admin", None))
            .await
            .unwrap();
        assert_eq!(result.audit_durability, AuditDurability::Uncertain);
        assert!(!root.path().join("remove.txt").exists());
        assert!(
            state
                .db
                .share_by_token("delete-audit-token")
                .unwrap()
                .unwrap()
                .active
        );
        assert_eq!(
            state.secure_root.pending_file_operations().unwrap().len(),
            1
        );

        fault
            .execute_batch("DROP TRIGGER fail_required_audit;")
            .unwrap();
        recover_pending_file_operations(&state).await.unwrap();
        recover_pending_file_operations(&state).await.unwrap();
        assert!(
            !state
                .db
                .share_by_token("delete-audit-token")
                .unwrap()
                .unwrap()
                .active
        );
        let events = state.db.list_audit(Some("path_deleted"), 10, 0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, "system");
        assert!(events[0].client_ip.is_none());
    }

    #[tokio::test]
    async fn rename_database_failure_after_publication_is_uncertain_not_retryable_failure() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("old.txt"), b"content").unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_share(
                "rename-database-token",
                None,
                "old.txt",
                false,
                &Permission::DownloadOnly,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let fault = install_share_update_failure(data.path());

        let result = rename(
            &state,
            "old.txt",
            "new.txt",
            AuditContext::new("admin", None),
        )
        .await
        .expect("a visible rename must be reported as uncertain, not failed");
        assert_eq!(result.audit_durability, AuditDurability::Uncertain);
        assert!(root.path().join("new.txt").is_file());
        assert_eq!(
            state
                .db
                .share_by_token("rename-database-token")
                .unwrap()
                .unwrap()
                .relative_path,
            "old.txt"
        );
        assert_eq!(
            state.secure_root.pending_file_operations().unwrap().len(),
            1
        );

        fault
            .execute_batch("DROP TRIGGER fail_share_update;")
            .unwrap();
        recover_pending_file_operations(&state).await.unwrap();
        assert_eq!(
            state
                .db
                .share_by_token("rename-database-token")
                .unwrap()
                .unwrap()
                .relative_path,
            "new.txt"
        );
    }

    #[tokio::test]
    async fn delete_database_failure_after_publication_is_uncertain_not_retryable_failure() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("remove.txt"), b"content").unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_share(
                "delete-database-token",
                None,
                "remove.txt",
                false,
                &Permission::DownloadOnly,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let fault = install_share_update_failure(data.path());

        let result = delete(&state, "remove.txt", None, AuditContext::new("admin", None))
            .await
            .expect("a visible deletion must be reported as uncertain, not failed");
        assert_eq!(result.audit_durability, AuditDurability::Uncertain);
        assert!(!root.path().join("remove.txt").exists());
        assert!(
            state
                .db
                .share_by_token("delete-database-token")
                .unwrap()
                .unwrap()
                .active
        );
        assert_eq!(
            state.secure_root.pending_file_operations().unwrap().len(),
            1
        );

        fault
            .execute_batch("DROP TRIGGER fail_share_update;")
            .unwrap();
        recover_pending_file_operations(&state).await.unwrap();
        assert!(
            !state
                .db
                .share_by_token("delete-database-token")
                .unwrap()
                .unwrap()
                .active
        );
    }

    #[tokio::test]
    async fn delete_reports_pending_and_retries_cleanup_start_and_batch_failures() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("tree")).unwrap();
        std::fs::write(root.path().join("tree/child.txt"), b"content").unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_share(
                "tree-token",
                None,
                "tree",
                true,
                &Permission::DownloadOnly,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();

        // Hold the sole worker until the synchronous result and durable
        // tombstone can be asserted. Its first broad scan fails to start; the
        // following attempt fails in run_batch.
        let cleanup_guard = state
            .storage_cleanup
            .serialization_for_test()
            .lock_owned()
            .await;
        state
            .secure_root
            .fail_next_cleanup_starts(io::ErrorKind::Other, 1);
        state
            .secure_root
            .fail_next_cleanup_batch(io::ErrorKind::Other);
        let cleanup_worker = state
            .storage_cleanup
            .start_worker(state.secure_root.clone())
            .unwrap();

        let result = delete(&state, "tree", Some("tree"), AuditContext::system())
            .await
            .unwrap();
        assert!(result.cleanup_pending);
        assert_eq!(result.deactivated_shares, 1);
        assert!(!root.path().join("tree").exists());
        assert_eq!(tombstone_paths(root.path()).len(), 1);
        assert!(
            !state
                .db
                .share_by_token("tree-token")
                .unwrap()
                .unwrap()
                .active
        );

        drop(cleanup_guard);
        for _ in 0..200 {
            if tombstone_paths(root.path()).is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            tombstone_paths(root.path()).is_empty(),
            "cleanup did not recover after injected start and batch failures"
        );
        cleanup_worker.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cleanup_shutdown_waits_for_a_running_blocking_batch() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        state.secure_root.before_next_cleanup_batch(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        let worker = state
            .storage_cleanup
            .start_worker(state.secure_root.clone())
            .unwrap();

        tokio::task::spawn_blocking(move || {
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("cleanup batch did not reach the test hook");
        })
        .await
        .unwrap();
        let mut shutdown = tokio::spawn(worker.shutdown());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut shutdown)
                .await
                .is_err(),
            "shutdown returned before the running blocking batch finished"
        );

        release_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), &mut shutdown)
            .await
            .expect("cleanup worker did not stop after the blocking batch returned")
            .unwrap()
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            state.storage_cleanup.serialization_for_test().lock_owned(),
        )
        .await
        .expect("cleanup mutex was not released after the worker stopped");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cleanup_shutdown_does_not_launch_the_next_batch() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let upload_staging = root
            .path()
            .join(crate::config::DEFAULT_INTERNAL_DIRECTORY_NAME)
            .join("uploads");
        for index in 0..=crate::storage_cleanup::CLEANUP_BATCH_ENTRIES {
            std::fs::write(
                upload_staging.join(format!(".vaultlink-{index:024}.part")),
                b"",
            )
            .unwrap();
        }
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        state.secure_root.before_next_cleanup_batch(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        let worker = state
            .storage_cleanup
            .start_worker(state.secure_root.clone())
            .unwrap();
        tokio::task::spawn_blocking(move || {
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("cleanup batch did not reach the test hook");
        })
        .await
        .unwrap();

        worker.request_shutdown();
        let mut join = tokio::spawn(worker.join());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut join)
                .await
                .is_err(),
            "shutdown returned before the active batch finished"
        );
        release_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), &mut join)
            .await
            .expect("cleanup worker did not stop after the active batch")
            .unwrap()
            .unwrap();

        let remaining = std::fs::read_dir(upload_staging)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| crate::secure_fs::is_upload_fragment_name(&entry.file_name()))
            .count();
        assert!(remaining > 0, "shutdown launched another cleanup batch");
        assert!(
            remaining < crate::storage_cleanup::CLEANUP_BATCH_ENTRIES + 1,
            "the active cleanup batch did not finish"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cleanup_shutdown_wakes_an_idle_worker_without_starting_another_pass() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let worker = state
            .storage_cleanup
            .start_worker(state.secure_root.clone())
            .unwrap();

        for _ in 0..100 {
            if state.storage_cleanup.pass_count_for_test() >= 1 {
                let guard = state
                    .storage_cleanup
                    .serialization_for_test()
                    .lock_owned()
                    .await;
                drop(guard);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let completed_passes = state.storage_cleanup.pass_count_for_test();
        assert_eq!(completed_passes, 1);

        tokio::time::timeout(std::time::Duration::from_secs(1), worker.shutdown())
            .await
            .expect("idle cleanup worker did not wake for shutdown")
            .unwrap();
        assert_eq!(
            state.storage_cleanup.pass_count_for_test(),
            completed_passes
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ten_thousand_cleanup_signals_keep_one_rate_limited_worker() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        state
            .secure_root
            .fail_next_cleanup_starts(io::ErrorKind::Other, 10_000);

        for _ in 0..10_000 {
            state.storage_cleanup.request_cleanup();
        }
        let worker = state
            .storage_cleanup
            .start_worker(state.secure_root.clone())
            .unwrap();
        assert!(matches!(
            state
                .storage_cleanup
                .start_worker(state.secure_root.clone()),
            Err(crate::storage_cleanup::StorageCleanupStartError::AlreadyRunning)
        ));

        tokio::time::sleep(std::time::Duration::from_millis(90)).await;
        let attempts = state.storage_cleanup.pass_count_for_test();
        assert!(attempts >= 2, "the failed cleanup was not retried");
        assert!(
            attempts <= 5,
            "coalesced requests bypassed the retry deadline: {attempts} attempts"
        );
        worker.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cleanup_signal_during_a_scan_schedules_one_follow_up_pass() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let cleanup = state.storage_cleanup.clone();
        state.secure_root.before_next_cleanup_batch(move || {
            cleanup.request_cleanup();
        });
        let worker = state
            .storage_cleanup
            .start_worker(state.secure_root.clone())
            .unwrap();

        for _ in 0..100 {
            if state.storage_cleanup.pass_count_for_test() >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(state.storage_cleanup.pass_count_for_test(), 2);
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn deleting_a_regular_file_finishes_without_pending_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("single.txt"), b"content").unwrap();
        let state = test_state(root.path(), data.path());

        let result = delete(&state, "single.txt", None, AuditContext::system())
            .await
            .unwrap();
        assert!(!result.cleanup_pending);
        assert!(tombstone_paths(root.path()).is_empty());
        assert!(!root.path().join("single.txt").exists());
    }

    #[tokio::test]
    async fn interrupted_rename_is_reconciled_with_share_paths() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("old.txt"), b"content").unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_share(
                "rename-token",
                None,
                "old.txt",
                false,
                &Permission::DownloadOnly,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let fault = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
        fault
            .execute_batch(
                "CREATE TRIGGER fail_share_rename
                 BEFORE UPDATE OF relative_path ON shares
                 BEGIN SELECT RAISE(ABORT, 'injected rename failure'); END;",
            )
            .unwrap();

        let outcome = rename(&state, "old.txt", "new.txt", AuditContext::system())
            .await
            .unwrap();
        assert_eq!(outcome.audit_durability, AuditDurability::Uncertain);
        assert!(!root.path().join("old.txt").exists());
        assert_eq!(
            std::fs::read(root.path().join("new.txt")).unwrap(),
            b"content"
        );
        assert_eq!(
            state
                .db
                .share_by_token("rename-token")
                .unwrap()
                .unwrap()
                .relative_path,
            "old.txt"
        );
        assert_eq!(
            state.secure_root.pending_file_operations().unwrap().len(),
            1
        );

        fault
            .execute_batch("DROP TRIGGER fail_share_rename;")
            .unwrap();
        recover_pending_file_operations(&state).await.unwrap();
        assert_eq!(
            state
                .db
                .share_by_token("rename-token")
                .unwrap()
                .unwrap()
                .relative_path,
            "new.txt"
        );
        assert!(state
            .secure_root
            .pending_file_operations()
            .unwrap()
            .is_empty());
        recover_pending_file_operations(&state).await.unwrap();
    }

    #[tokio::test]
    async fn interrupted_delete_is_reconciled_with_share_activation() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("remove.txt"), b"content").unwrap();
        let state = test_state(root.path(), data.path());
        state.db.create_admin("admin", "hash", "secret").unwrap();
        state
            .db
            .create_share(
                "delete-token",
                None,
                "remove.txt",
                false,
                &Permission::DownloadOnly,
                None,
                None,
                None,
                1,
                None,
                &UploadConflictStrategy::Reject,
            )
            .unwrap();
        let fault = rusqlite::Connection::open(data.path().join("data.sqlite")).unwrap();
        fault
            .execute_batch(
                "CREATE TRIGGER fail_share_deactivate
                 BEFORE UPDATE OF active ON shares
                 BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END;",
            )
            .unwrap();

        let outcome = delete(&state, "remove.txt", None, AuditContext::system())
            .await
            .unwrap();
        assert_eq!(outcome.audit_durability, AuditDurability::Uncertain);
        assert!(!root.path().join("remove.txt").exists());
        assert!(
            state
                .db
                .share_by_token("delete-token")
                .unwrap()
                .unwrap()
                .active
        );
        assert_eq!(
            state.secure_root.pending_file_operations().unwrap().len(),
            1
        );

        fault
            .execute_batch("DROP TRIGGER fail_share_deactivate;")
            .unwrap();
        recover_pending_file_operations(&state).await.unwrap();
        assert!(
            !state
                .db
                .share_by_token("delete-token")
                .unwrap()
                .unwrap()
                .active
        );
        assert!(state
            .secure_root
            .pending_file_operations()
            .unwrap()
            .is_empty());
        recover_pending_file_operations(&state).await.unwrap();
    }
}
