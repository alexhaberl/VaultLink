use std::{
    borrow::Borrow,
    sync::atomic::{AtomicU64, Ordering},
};

use tokio::io::AsyncWriteExt as _;

use crate::{secure_fs::PendingUpload, AppState};

const STORAGE_RESERVE_BYTES: u64 = 64 * 1_000_000;
static UPLOAD_BYTES_RESERVED: AtomicU64 = AtomicU64::new(0);

pub(crate) async fn storage_has_room(
    state: &(impl Borrow<AppState> + ?Sized),
    needed: u64,
) -> std::io::Result<bool> {
    let state = state.borrow();
    state
        .disk_stats_cache()
        .get(state.secure_root().display_root())
        .await
        .map(|stats| {
            stats
                .free
                .saturating_sub(STORAGE_RESERVE_BYTES)
                .saturating_sub(needed)
                > 0
        })
}

pub(crate) struct UploadChunkReservation {
    bytes: u64,
}

pub(crate) enum StorageReservationError {
    CapacityUnavailable,
    InsufficientStorage,
}

impl UploadChunkReservation {
    pub(crate) async fn acquire(
        state: &(impl Borrow<AppState> + ?Sized),
        bytes: u64,
    ) -> Result<Self, StorageReservationError> {
        let state = state.borrow();
        let stats = state
            .disk_stats_cache()
            .get(state.secure_root().display_root())
            .await
            .map_err(|_| StorageReservationError::CapacityUnavailable)?;
        loop {
            let reserved = UPLOAD_BYTES_RESERVED.load(Ordering::Acquire);
            if stats
                .free
                .saturating_sub(STORAGE_RESERVE_BYTES)
                .saturating_sub(reserved)
                <= bytes
            {
                return Err(StorageReservationError::InsufficientStorage);
            }
            let next = reserved
                .checked_add(bytes)
                .ok_or(StorageReservationError::InsufficientStorage)?;
            if UPLOAD_BYTES_RESERVED
                .compare_exchange_weak(reserved, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(Self { bytes });
            }
        }
    }
}

impl Drop for UploadChunkReservation {
    fn drop(&mut self) {
        UPLOAD_BYTES_RESERVED.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

pub(crate) fn storage_full_error(error: &std::io::Error) -> bool {
    const ENOSPC: i32 = 28;
    const EDQUOT: i32 = 122;
    error.kind() == std::io::ErrorKind::StorageFull
        || matches!(error.raw_os_error(), Some(ENOSPC | EDQUOT | 112))
}

pub(crate) enum StagedFileError {
    TooLarge,
    CapacityUnavailable,
    InsufficientStorage,
    Io(std::io::Error),
}

/// Shared transport-neutral file-staging owner. Public and administrator
/// uploads share this bounded write/flush/sync primitive, but retain separate
/// authorization, publication, audit, and response adapters.
pub(crate) struct StagedUploadFile {
    output: Option<tokio::fs::File>,
    pending: PendingUpload,
    total: u64,
}

impl StagedUploadFile {
    pub(crate) fn new(pending: PendingUpload, file: std::fs::File) -> Self {
        Self {
            output: Some(tokio::fs::File::from_std(file)),
            pending,
            total: 0,
        }
    }

    pub(crate) fn total(&self) -> u64 {
        self.total
    }

    pub(crate) async fn write_chunk(
        &mut self,
        state: &(impl Borrow<AppState> + ?Sized),
        maximum: u64,
        chunk: &[u8],
    ) -> Result<(), StagedFileError> {
        let chunk_len = u64::try_from(chunk.len()).map_err(|_| StagedFileError::TooLarge)?;
        let new_total = self
            .total
            .checked_add(chunk_len)
            .filter(|total| *total <= maximum)
            .ok_or(StagedFileError::TooLarge)?;
        let _reservation = UploadChunkReservation::acquire(state, chunk_len)
            .await
            .map_err(|error| match error {
                StorageReservationError::CapacityUnavailable => {
                    StagedFileError::CapacityUnavailable
                }
                StorageReservationError::InsufficientStorage => {
                    StagedFileError::InsufficientStorage
                }
            })?;
        self.output
            .as_mut()
            .expect("staged output remains open while receiving data")
            .write_all(chunk)
            .await
            .map_err(StagedFileError::Io)?;
        self.total = new_total;
        Ok(())
    }

    pub(crate) async fn flush(&mut self) -> Result<(), StagedFileError> {
        self.output
            .as_mut()
            .expect("staged output can only be flushed while open")
            .flush()
            .await
            .map_err(StagedFileError::Io)
    }

    pub(crate) async fn sync_and_close(&mut self) -> Result<(), StagedFileError> {
        self.output
            .as_mut()
            .expect("staged output can only be synced once")
            .sync_all()
            .await
            .map_err(StagedFileError::Io)?;
        drop(
            self.output
                .take()
                .expect("staged output remains open until sync completes"),
        );
        Ok(())
    }

    pub(crate) async fn finish(&mut self) -> Result<(), StagedFileError> {
        self.flush().await?;
        self.sync_and_close().await
    }

    pub(crate) fn into_parts(self) -> (PendingUpload, u64) {
        debug_assert!(self.output.is_none());
        (self.pending, self.total)
    }
}
