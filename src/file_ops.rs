use std::io;

use thiserror::Error;

use crate::{
    path_security,
    secure_fs::{EntryKind, EntryStatus, SecureRoot, UploadFragmentCleanup},
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
    let _guard = state.storage_mutation.lock().await;
    let secure_root = state.secure_root.clone();
    let path = tokio::task::spawn_blocking(move || secure_root.create_directory(&parent, &name))
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
    let _guard = state.storage_mutation.lock().await;
    let secure_root = state.secure_root.clone();
    let database = state.db.clone();
    tokio::task::spawn_blocking(move || {
        let staged = secure_root.stage_rename(&path, &new_name).map_err(map_io)?;
        let old_path = staged.original_path().to_string();
        let new_path = staged.new_path().to_string();
        let kind = staged.kind();
        let updated_shares =
            database.rename_share_paths(&old_path, &new_path, kind == EntryKind::Directory)?;
        staged.commit();
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
    let _guard = state.storage_mutation.lock().await;
    let secure_root = state.secure_root.clone();
    let cleanup_root = secure_root.clone();
    let cleanup_lock = state.storage_cleanup.clone();
    let database = state.db.clone();
    let result = tokio::task::spawn_blocking(move || {
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
        let deactivated_shares = database
            .deactivate_shares_for_path(&original_path, status.kind == EntryKind::Directory)?;
        let committed = staged.commit().map_err(map_io)?;
        Ok::<_, FileOperationError>((
            DeleteResult {
                path: original_path,
                kind: status.kind,
                deactivated_shares,
                cleanup_pending: committed.cleanup_pending,
            },
            committed.tombstone_path,
        ))
    })
    .await??;
    if let Some(tombstone_path) = result.1 {
        spawn_deletion_cleanup(cleanup_root, cleanup_lock, tombstone_path);
    }
    Ok(result.0)
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

fn spawn_deletion_cleanup(
    secure_root: SecureRoot,
    cleanup_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    tombstone_path: String,
) {
    tokio::spawn(async move {
        loop {
            let cleanup_guard = cleanup_lock.lock().await;
            let start_root = secure_root.clone();
            let start_path = tombstone_path.clone();
            let cleanup = tokio::task::spawn_blocking(move || {
                start_root
                    .start_deletion_cleanup(&start_path)
                    .or_else(|_| start_root.start_upload_fragment_cleanup())
            })
            .await;
            let cleanup = match cleanup {
                Ok(Ok(cleanup)) => cleanup,
                Ok(Err(error)) => {
                    tracing::warn!(%error, %tombstone_path, "could not start deletion cleanup");
                    drop(cleanup_guard);
                    tokio::time::sleep(CLEANUP_RETRY_DELAY).await;
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, %tombstone_path, "deletion cleanup task failed to start");
                    drop(cleanup_guard);
                    tokio::time::sleep(CLEANUP_RETRY_DELAY).await;
                    continue;
                }
            };
            if run_cleanup(cleanup, &tombstone_path).await {
                return;
            }
            drop(cleanup_guard);
            tokio::time::sleep(CLEANUP_RETRY_DELAY).await;
        }
    });
}

async fn run_cleanup(mut cleanup: UploadFragmentCleanup, tombstone_path: &str) -> bool {
    let mut failures = 0usize;
    loop {
        let result = tokio::task::spawn_blocking(move || {
            let batch = cleanup.run_batch(CLEANUP_BATCH_ENTRIES);
            (cleanup, batch)
        })
        .await;
        let batch = match result {
            Ok((next, Ok(batch))) => {
                cleanup = next;
                batch
            }
            Ok((_next, Err(error))) => {
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
}
