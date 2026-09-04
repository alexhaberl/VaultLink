use std::io;

use chrono::Utc;
use tokio::io::AsyncSeekExt as _;

use crate::{
    db::{Database, Share},
    file_ops::{self, FileOperationError},
    internal_reporting::{report_internal, InternalOperation, ReportedInternalError},
    path_security,
    policy::{self, ShareAvailability},
    secure_fs::{SecureDirectory, SecureFile},
    storage_authority::StorageReadGuard,
    AppState,
};

#[derive(Clone)]
pub(crate) struct PublicTransferService {
    state: AppState,
}

pub(crate) enum PublicTransferError {
    NotFound,
    Inactive,
    Expired,
    Changed,
    StorageUnavailable,
    Capacity,
    AuditUnavailable,
    InvalidFilePath,
    MissingFilePath,
    InvalidZipPath,
    FileUnavailable,
    ShareTargetUnavailable,
    TransferLimitReached,
    TransferShareUnavailable,
    RateLimited,
    ConcurrentDownloads,
    NotFile,
    PreviewLimitReached,
    RangeNotSatisfiable(u64),
    Internal(ReportedInternalError),
}

pub(crate) struct PreparedDownload {
    pub(crate) share: Share,
    pub(crate) relative_file: String,
    file: std::fs::File,
    length: u64,
}

pub(crate) struct PreparedFileSelection {
    pub(crate) file: tokio::fs::File,
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) full_length: u64,
    pub(crate) response_length: u64,
    pub(crate) partial: bool,
}

pub(crate) enum RangeSelectionError {
    Unsatisfied { full_length: u64 },
    Internal(ReportedInternalError),
}

pub(crate) struct PreparedZipScope {
    pub(crate) share: Share,
    pub(crate) directory: SecureDirectory,
    pub(crate) subpath: String,
}

pub(crate) enum PreparedPreviewTarget {
    Directory(SecureDirectory),
    File(SecureFile),
}

enum RawPreviewOpenError {
    Unavailable,
    Metadata(io::Error),
}

pub(crate) struct PreparedPreview {
    pub(crate) share: Share,
    pub(crate) relative_file: String,
    pub(crate) requested_path: String,
    pub(crate) target: PreparedPreviewTarget,
}

impl PublicTransferService {
    pub(crate) fn new(state: AppState) -> Self {
        Self { state }
    }

    pub(crate) fn state(&self) -> &AppState {
        &self.state
    }

    pub(crate) async fn share_for_transfer(
        &self,
        token: &str,
    ) -> Result<Share, PublicTransferError> {
        let share = self.find_share(token).await?;
        match policy::share_availability(&share, Utc::now()) {
            ShareAvailability::Available | ShareAvailability::LimitReached => Ok(share),
            ShareAvailability::Inactive => Err(PublicTransferError::Inactive),
            ShareAvailability::Expired => Err(PublicTransferError::Expired),
        }
    }

    pub(crate) async fn share(&self, token: &str) -> Result<Share, PublicTransferError> {
        let share = self.find_share(token).await?;
        match policy::share_availability(&share, Utc::now()) {
            ShareAvailability::Available => Ok(share),
            ShareAvailability::Inactive | ShareAvailability::LimitReached => {
                Err(PublicTransferError::Inactive)
            }
            ShareAvailability::Expired => Err(PublicTransferError::Expired),
        }
    }

    pub(crate) async fn storage_share_for_transfer(
        &self,
        token: &str,
        expected_id: i64,
    ) -> Result<(Share, StorageReadGuard), PublicTransferError> {
        let guard = file_ops::acquire_storage_read(&self.state)
            .await
            .map_err(map_storage_error)?;
        let share = self.share_for_transfer(token).await?;
        if share.id != expected_id {
            return Err(PublicTransferError::Changed);
        }
        Ok((share, guard))
    }

    pub(crate) async fn storage_share(
        &self,
        token: &str,
        expected_id: i64,
    ) -> Result<(Share, StorageReadGuard), PublicTransferError> {
        let guard = file_ops::acquire_storage_read(&self.state)
            .await
            .map_err(map_storage_error)?;
        let share = self.share(token).await?;
        if share.id != expected_id {
            return Err(PublicTransferError::Changed);
        }
        Ok((share, guard))
    }

    pub(crate) async fn prepare_download(
        &self,
        share: Share,
        requested_path: Option<String>,
        storage_guard: StorageReadGuard,
    ) -> Result<PreparedDownload, PublicTransferError> {
        let relative_file = download_relative_path(&share, requested_path)?;
        let open_root = self.state.secure_root().clone();
        let share_path = share.relative_path.clone();
        let open_relative_file = relative_file.clone();
        let share_is_directory = share.is_directory;
        let (file, metadata) = tokio::task::spawn_blocking(move || {
            let _storage_guard = storage_guard;
            let file = if share_is_directory {
                open_root
                    .bind_directory(&share_path)
                    .and_then(|directory| directory.open_file(&open_relative_file))
                    .map(SecureFile::into_file)
            } else {
                open_root.bind_file(&share_path).map(SecureFile::into_file)
            }?;
            let metadata = file.metadata()?;
            Ok::<_, io::Error>((file, metadata))
        })
        .await
        .map_err(|error| {
            PublicTransferError::Internal(report_internal(
                InternalOperation::WebDownloadOpenTaskJoin,
                error,
            ))
        })?
        .map_err(|_| PublicTransferError::FileUnavailable)?;
        if !metadata.is_file() {
            return Err(PublicTransferError::NotFile);
        }
        Ok(PreparedDownload {
            share,
            relative_file,
            file,
            length: metadata.len(),
        })
    }

    pub(crate) async fn prepare_zip_scope(
        &self,
        share: Share,
        requested_path: Option<&str>,
        storage_guard: StorageReadGuard,
    ) -> Result<PreparedZipScope, PublicTransferError> {
        let subpath = path_security::validate_relative(requested_path.unwrap_or_default())
            .map_err(|_| PublicTransferError::InvalidZipPath)?
            .to_string_lossy()
            .replace('\\', "/");
        let root = self.state.secure_root().clone();
        let share_path = share.relative_path.clone();
        let directory = tokio::task::spawn_blocking(move || {
            let _storage_guard = storage_guard;
            root.bind_directory(&share_path)
        })
        .await
        .map_err(|error| {
            PublicTransferError::Internal(report_internal(
                InternalOperation::WebZipScopeOpenTaskJoin,
                error,
            ))
        })?
        .map_err(|_| PublicTransferError::ShareTargetUnavailable)?;
        Ok(PreparedZipScope {
            share,
            directory,
            subpath,
        })
    }

    pub(crate) async fn prepare_preview(
        &self,
        share: Share,
        requested_path: Option<String>,
        storage_guard: StorageReadGuard,
    ) -> Result<PreparedPreview, PublicTransferError> {
        let requested_path = requested_path.unwrap_or_default();
        let relative_file = if share.is_directory {
            if requested_path.is_empty() {
                return Err(PublicTransferError::MissingFilePath);
            }
            requested_path.clone()
        } else {
            share.relative_path.clone()
        };
        let root = self.state.secure_root().clone();
        let share_path = share.relative_path.clone();
        let is_directory = share.is_directory;
        let target = tokio::task::spawn_blocking(move || {
            let _storage_guard = storage_guard;
            if is_directory {
                root.bind_directory(&share_path)
                    .map(PreparedPreviewTarget::Directory)
            } else {
                root.bind_file(&share_path).map(PreparedPreviewTarget::File)
            }
        })
        .await
        .map_err(|error| {
            PublicTransferError::Internal(report_internal(
                InternalOperation::WebPublicPreviewScopeOpenJoin,
                error,
            ))
        })?
        .map_err(|_| PublicTransferError::ShareTargetUnavailable)?;
        Ok(PreparedPreview {
            share,
            relative_file,
            requested_path,
            target,
        })
    }

    async fn find_share(&self, token: &str) -> Result<Share, PublicTransferError> {
        let database = self.state.db().clone();
        let token = token.to_owned();
        run_database_read(database, move |database| database.share_by_token(&token))
            .await?
            .ok_or(PublicTransferError::NotFound)
    }
}

impl PreparedDownload {
    pub(crate) async fn select(
        self,
        requested_range: Option<&str>,
    ) -> Result<PreparedFileSelection, RangeSelectionError> {
        select_file(self.file, self.length, requested_range).await
    }
}

impl PreparedPreview {
    pub(crate) async fn select_raw(
        self,
        maximum: u64,
        requested_range: Option<&str>,
    ) -> Result<PreparedFileSelection, PublicTransferError> {
        let relative_file = self.relative_file;
        let (file, metadata) = tokio::task::spawn_blocking(move || {
            let file = match self.target {
                PreparedPreviewTarget::Directory(directory) => directory
                    .open_file(&relative_file)
                    .map(SecureFile::into_file)
                    .map_err(|_| RawPreviewOpenError::Unavailable)?,
                PreparedPreviewTarget::File(file) => file.into_file(),
            };
            let metadata = file.metadata().map_err(RawPreviewOpenError::Metadata)?;
            Ok::<_, RawPreviewOpenError>((file, metadata))
        })
        .await
        .map_err(|error| {
            PublicTransferError::Internal(report_internal(
                InternalOperation::WebRawPreviewOpenJoin,
                error,
            ))
        })?
        .map_err(|error| match error {
            RawPreviewOpenError::Unavailable => PublicTransferError::FileUnavailable,
            RawPreviewOpenError::Metadata(error) => PublicTransferError::Internal(report_internal(
                InternalOperation::WebRawPreviewFileMetadata,
                error,
            )),
        })?;
        if !metadata.is_file() {
            return Err(PublicTransferError::NotFile);
        }
        let length = metadata.len();
        if length > maximum {
            return Err(PublicTransferError::PreviewLimitReached);
        }
        select_raw_file(file, length, requested_range).await
    }
}

async fn select_raw_file(
    file: std::fs::File,
    length: u64,
    requested_range: Option<&str>,
) -> Result<PreparedFileSelection, PublicTransferError> {
    let range = match requested_range {
        Some(value) => Some(
            crate::range::parse_byte_range(value, length)
                .map_err(|_| PublicTransferError::RangeNotSatisfiable(length))?,
        ),
        None => None,
    };
    let (start, end) = range.unwrap_or((0, length.saturating_sub(1)));
    let response_length = if length == 0 { 0 } else { end - start + 1 };
    let mut file = tokio::fs::File::from_std(file);
    if start > 0 {
        file.seek(io::SeekFrom::Start(start))
            .await
            .map_err(|error| {
                PublicTransferError::Internal(report_internal(
                    InternalOperation::WebRawPreviewSeek,
                    error,
                ))
            })?;
    }
    Ok(PreparedFileSelection {
        file,
        start,
        end,
        full_length: length,
        response_length,
        partial: range.is_some(),
    })
}

pub(crate) async fn select_file(
    file: std::fs::File,
    length: u64,
    requested_range: Option<&str>,
) -> Result<PreparedFileSelection, RangeSelectionError> {
    let range = match requested_range {
        Some(value) => Some(crate::range::parse_byte_range(value, length).map_err(|_| {
            RangeSelectionError::Unsatisfied {
                full_length: length,
            }
        })?),
        None => None,
    };
    let (start, end) = range.unwrap_or((0, length.saturating_sub(1)));
    let response_length = if length == 0 { 0 } else { end - start + 1 };
    let mut file = tokio::fs::File::from_std(file);
    if start > 0 {
        file.seek(io::SeekFrom::Start(start))
            .await
            .map_err(|error| {
                RangeSelectionError::Internal(report_internal(
                    InternalOperation::WebDownloadSeek,
                    error,
                ))
            })?;
    }
    Ok(PreparedFileSelection {
        file,
        start,
        end,
        full_length: length,
        response_length,
        partial: range.is_some(),
    })
}

fn download_relative_path(
    share: &Share,
    requested_path: Option<String>,
) -> Result<String, PublicTransferError> {
    if !share.is_directory {
        return Ok(share.relative_path.clone());
    }
    let requested_path = requested_path.ok_or(PublicTransferError::MissingFilePath)?;
    path_security::validate_relative(&requested_path)
        .map_err(|_| PublicTransferError::InvalidFilePath)
        .map(|path| path.to_string_lossy().replace('\\', "/"))
}

fn map_storage_error(error: FileOperationError) -> PublicTransferError {
    match error {
        FileOperationError::DatabaseCapacity => PublicTransferError::Capacity,
        FileOperationError::Database(database_error)
            if crate::db::is_audit_unavailable(&database_error) =>
        {
            PublicTransferError::AuditUnavailable
        }
        FileOperationError::Database(database_error)
            if crate::db::is_sqlite_busy_or_locked(&database_error) =>
        {
            PublicTransferError::Capacity
        }
        _ => PublicTransferError::StorageUnavailable,
    }
}

pub(super) async fn run_database_read<T, F>(
    database: Database,
    operation: F,
) -> Result<T, PublicTransferError>
where
    T: Send + 'static,
    F: FnOnce(&Database) -> rusqlite::Result<T> + Send + 'static,
{
    let permit = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        database.acquire_runtime_permit(),
    )
    .await
    .map_err(|_| PublicTransferError::Capacity)?
    .map_err(|_| PublicTransferError::Capacity)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation(&database)
    })
    .await
    .map_err(|error| {
        PublicTransferError::Internal(report_internal(
            InternalOperation::HttpAuthDatabaseReadJoin,
            error,
        ))
    })?
    .map_err(|error| {
        if crate::db::is_audit_unavailable(&error) {
            PublicTransferError::AuditUnavailable
        } else if crate::db::is_sqlite_busy_or_locked(&error) {
            PublicTransferError::Capacity
        } else {
            PublicTransferError::Internal(report_internal(
                InternalOperation::HttpAuthDatabaseFailure,
                error,
            ))
        }
    })
}
