use std::io;

use thiserror::Error;

use crate::{
    path_security,
    secure_fs::{EntryKind, EntryStatus, FileOperationRecovery, SecureRoot, UploadFragmentCleanup},
    AppState,
};

const CLEANUP_BATCH_ENTRIES: usize = 4096;
#[cfg(not(test))]
const CLEANUP_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(test)]
const CLEANUP_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(10);

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
}

#[derive(Debug)]
pub struct RenameResult {
    pub path: String,
    pub kind: EntryKind,
    pub updated_shares: usize,
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
}

pub async fn create_directory(
    state: &AppState,
    parent: &str,
    name: &str,
) -> Result<CreateDirectoryResult, FileOperationError> {
    let parent = normalize(parent, true)?;
    let name = validate_name(name)?;
    let guard = state.storage_mutation.clone().lock_owned().await;
    let guard = recover_pending_file_operations_with_guard(state, guard).await?;
    let secure_root = state.secure_root.clone();
    let path = tokio::task::spawn_blocking(move || {
        let _storage_guard = guard;
        secure_root.create_directory(&parent, &name)
    })
    .await?
    .map_err(map_io)?;
    Ok(CreateDirectoryResult { path })
}

pub async fn rename(
    state: &AppState,
    path: &str,
    new_name: &str,
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
        let updated_shares =
            database.rename_share_paths(&old_path, &new_path, kind == EntryKind::Directory)?;
        staged.commit().map_err(map_io)?;
        Ok(RenameResult {
            path: new_path,
            kind,
            updated_shares,
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
) -> Result<DeleteResult, FileOperationError> {
    let path = normalize(path, false)?;
    let confirmation = confirm_name.map(str::to_string);
    let guard = state.storage_mutation.clone().lock_owned().await;
    let guard = recover_pending_file_operations_with_guard(state, guard).await?;
    let secure_root = state.secure_root.clone();
    let cleanup_root = secure_root.clone();
    let cleanup_lock = state.storage_cleanup.clone();
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
        let deactivated_shares = database
            .deactivate_shares_for_path(&original_path, status.kind == EntryKind::Directory)?;
        let committed = committed.complete().map_err(map_io)?;
        if let Some(tombstone_path) = committed.tombstone_path {
            // Enqueue cleanup from the non-cancellable blocking finalizer. If
            // the HTTP future is dropped, a journal-free tombstone must not be
            // stranded until the next process restart.
            spawn_deletion_cleanup(cleanup_root, cleanup_lock, tombstone_path);
        }
        Ok::<_, FileOperationError>(DeleteResult {
            path: original_path,
            kind: status.kind,
            deactivated_shares,
            cleanup_pending: committed.cleanup_pending,
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
    let cleanup_root = secure_root.clone();
    let cleanup_lock = state.storage_cleanup.clone();
    let guard = tokio::task::spawn_blocking(move || {
        // spawn_blocking tasks continue after their awaiting request is
        // cancelled. Owning the guard here keeps recovery serialized until the
        // task has actually finished.
        let cleanup_paths = recover_pending_file_operations_blocking(&secure_root, &database)?;
        for tombstone_path in cleanup_paths {
            // Schedule before returning the guard/result: spawn_blocking keeps
            // running after request cancellation, while code after `.await`
            // would be skipped with its result discarded.
            spawn_deletion_cleanup(cleanup_root.clone(), cleanup_lock.clone(), tombstone_path);
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
                database.rename_share_paths(&original_path, &new_path, is_directory)?;
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
                database.deactivate_shares_for_path(&original_path, is_directory)?;
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

fn spawn_deletion_cleanup(
    secure_root: SecureRoot,
    cleanup_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    tombstone_path: String,
) {
    tokio::spawn(async move {
        loop {
            let cleanup_guard = cleanup_lock.clone().lock_owned().await;
            let start_root = secure_root.clone();
            let start_path = tombstone_path.clone();
            let cleanup = tokio::task::spawn_blocking(move || {
                let cleanup = start_root
                    .start_deletion_cleanup(&start_path)
                    .or_else(|_| start_root.start_upload_fragment_cleanup());
                (cleanup_guard, cleanup)
            })
            .await;
            let (cleanup_guard, cleanup) = match cleanup {
                Ok((cleanup_guard, Ok(cleanup))) => (cleanup_guard, cleanup),
                Ok((_cleanup_guard, Err(error))) => {
                    tracing::warn!(%error, %tombstone_path, "could not start deletion cleanup");
                    tokio::time::sleep(CLEANUP_RETRY_DELAY).await;
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, %tombstone_path, "deletion cleanup task failed to start");
                    tokio::time::sleep(CLEANUP_RETRY_DELAY).await;
                    continue;
                }
            };
            if run_cleanup(cleanup, &tombstone_path, cleanup_guard).await {
                return;
            }
            tokio::time::sleep(CLEANUP_RETRY_DELAY).await;
        }
    });
}

async fn run_cleanup(
    mut cleanup: UploadFragmentCleanup,
    tombstone_path: &str,
    mut cleanup_guard: tokio::sync::OwnedMutexGuard<()>,
) -> bool {
    let mut failures = 0usize;
    loop {
        let result = tokio::task::spawn_blocking(move || {
            let batch = cleanup.run_batch(CLEANUP_BATCH_ENTRIES);
            (cleanup, cleanup_guard, batch)
        })
        .await;
        let batch = match result {
            Ok((next, next_guard, Ok(batch))) => {
                cleanup = next;
                cleanup_guard = next_guard;
                batch
            }
            Ok((_next, _cleanup_guard, Err(error))) => {
                tracing::warn!(%error, %tombstone_path, "could not continue deletion cleanup");
                return false;
            }
            Err(error) => {
                tracing::warn!(%error, %tombstone_path, "deletion cleanup worker failed");
                return false;
            }
        };
        failures = failures.saturating_add(batch.failed);
        if batch.complete {
            tracing::info!(%tombstone_path, removed = batch.removed, failed = failures, "deletion cleanup completed");
            return failures == 0;
        }
        tokio::task::yield_now().await;
    }
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
                internal_directory: None,
                require_mount: false,
                external_writers: false,
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

        // Hold the worker until the synchronous result and durable tombstone can
        // be asserted. Two start errors cover both the targeted cleanup and its
        // broad cleanup fallback; the following attempt fails in run_batch.
        let cleanup_guard = state.storage_cleanup.lock().await;
        state
            .secure_root
            .fail_next_cleanup_starts(io::ErrorKind::Other, 2);
        state
            .secure_root
            .fail_next_cleanup_batch(io::ErrorKind::Other);

        let result = delete(&state, "tree", Some("tree")).await.unwrap();
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
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_cleanup_task_keeps_mutex_until_blocking_batch_returns() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let state = test_state(root.path(), data.path());
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        state.secure_root.before_next_cleanup_batch(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        let cleanup = state.secure_root.start_upload_fragment_cleanup().unwrap();
        let cleanup_guard = state.storage_cleanup.clone().lock_owned().await;
        let worker = tokio::spawn(run_cleanup(cleanup, "test-cleanup", cleanup_guard));

        tokio::task::spawn_blocking(move || {
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("cleanup batch did not reach the test hook");
        })
        .await
        .unwrap();
        worker.abort();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                state.storage_cleanup.clone().lock_owned(),
            )
            .await
            .is_err(),
            "cancelling the async wrapper released the cleanup mutex early"
        );

        release_tx.send(()).unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            state.storage_cleanup.clone().lock_owned(),
        )
        .await
        .expect("cleanup mutex was not released after the blocking batch returned");
    }

    #[tokio::test]
    async fn deleting_a_regular_file_finishes_without_pending_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("single.txt"), b"content").unwrap();
        let state = test_state(root.path(), data.path());

        let result = delete(&state, "single.txt", None).await.unwrap();
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

        assert!(matches!(
            rename(&state, "old.txt", "new.txt").await,
            Err(FileOperationError::Database(_))
        ));
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

        assert!(matches!(
            delete(&state, "remove.txt", None).await,
            Err(FileOperationError::Database(_))
        ));
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
