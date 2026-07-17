use std::{
    collections::VecDeque,
    io::{self, Read, Seek, Write},
    path::Path,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};

#[cfg(test)]
use std::sync::{Arc, OnceLock};

use axum::{
    body::{Body, Bytes},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::Response,
};
use futures_util::Stream;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::{
    policy::PreviewKind, range::parse_byte_range, runtime::RuntimeSettings, secure_fs::SecureFile,
    AppState,
};

use super::{
    common::{internal, join_display, preview_kind, DirectoryAccess},
    rendering::storage_full_error,
    AppError, Result,
};

const ZIP_CHUNK_SIZE: usize = 64 * 1024;
const ZIP_CHANNEL_CHUNKS: usize = 8;
const ZIP_TEMP_MIN_RESERVE: u64 = 64 * 1024 * 1024;
pub(super) const ZIP64_VERSION: u16 = 45;
const ZIP_LOCAL_HEADER_SIZE: u64 = 30;
const ZIP_CENTRAL_HEADER_SIZE: u64 = 46;
const ZIP64_DATA_DESCRIPTOR_SIZE: u64 = 24;
pub(super) const ZIP64_LOCAL_EXTRA_SIZE: u64 = 20;
pub(super) const ZIP64_CENTRAL_EXTRA_SIZE: u64 = 28;
pub(super) const ZIP64_EXTRA_PAYLOAD_SIZE: u16 = 24;
pub(super) const ZIP64_SIZE_FIELDS_SIZE: u16 = 16;
pub(super) const ZIP_EOCD_SIZE: u64 = 22;
const ZIP64_END_RECORDS_SIZE: u64 = 76;
const ZIP64_ENTRY_FIXED_SIZE: u64 = ZIP_LOCAL_HEADER_SIZE
    + ZIP64_LOCAL_EXTRA_SIZE
    + ZIP64_DATA_DESCRIPTOR_SIZE
    + ZIP_CENTRAL_HEADER_SIZE
    + ZIP64_CENTRAL_EXTRA_SIZE;
const ZIP64_ARCHIVE_END_SIZE: u64 = ZIP_EOCD_SIZE + ZIP64_END_RECORDS_SIZE;
static ZIP_TEMP_RESERVED: AtomicU64 = AtomicU64::new(0);

pub(super) struct ZipTempReservation {
    bytes: u64,
}

impl ZipTempReservation {
    pub(super) async fn acquire(
        state: &AppState,
        estimated_bytes: u64,
    ) -> io::Result<Option<Self>> {
        let safety = ZIP_TEMP_MIN_RESERVE.max(estimated_bytes / 10);
        let Some(required) = estimated_bytes.checked_add(safety) else {
            return Ok(None);
        };
        let available = state
            .disk_stats_cache
            .get(&std::env::temp_dir())
            .await?
            .free;
        loop {
            let reserved = ZIP_TEMP_RESERVED.load(Ordering::Acquire);
            if available.saturating_sub(reserved) < required {
                return Ok(None);
            }
            let Some(next) = reserved.checked_add(estimated_bytes) else {
                return Ok(None);
            };
            if ZIP_TEMP_RESERVED
                .compare_exchange_weak(reserved, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(Some(Self {
                    bytes: estimated_bytes,
                }));
            }
        }
    }

    #[cfg(test)]
    pub(super) fn acquire_unchecked_for_test(estimated_bytes: u64) -> Self {
        ZIP_TEMP_RESERVED.fetch_add(estimated_bytes, Ordering::AcqRel);
        Self {
            bytes: estimated_bytes,
        }
    }
}

impl Drop for ZipTempReservation {
    fn drop(&mut self) {
        ZIP_TEMP_RESERVED.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

#[cfg(test)]
pub(super) fn zip_temp_reserved_bytes_for_test() -> u64 {
    ZIP_TEMP_RESERVED.load(Ordering::Acquire)
}

#[derive(Debug)]
pub(super) enum ZipBuildError {
    Limit(&'static str),
    Source(io::Error),
    Output(io::Error),
}

impl ZipBuildError {
    fn into_io(self) -> io::Error {
        match self {
            Self::Limit(message) => io::Error::new(io::ErrorKind::InvalidData, message),
            Self::Source(error) | Self::Output(error) => error,
        }
    }

    pub(super) fn is_output_capacity_error(&self) -> bool {
        matches!(self, Self::Output(error) if storage_full_error(error))
    }
}

#[derive(Clone)]
pub(super) struct ZipFilePlan {
    pub(super) source_path: String,
    pub(super) archive_name: String,
    pub(super) scanned_len: u64,
    pub(super) is_directory: bool,
}

#[derive(Clone)]
pub(super) struct ZipPlan {
    pub(super) files: Vec<ZipFilePlan>,
    pub(super) max_data_size: u64,
    pub(super) estimated_archive_size: u64,
}

pub(super) fn estimate_zip_archive_size(
    files: &[ZipFilePlan],
) -> std::result::Result<u64, ZipBuildError> {
    let mut archive_size = ZIP64_ARCHIVE_END_SIZE;
    for file in files {
        let name_len = u64::try_from(file.archive_name.len())
            .map_err(|_| ZipBuildError::Limit("zip entry name is too long"))?;
        let names_size = name_len
            .checked_mul(2)
            .ok_or(ZipBuildError::Limit("zip archive size overflow"))?;
        archive_size = archive_size
            .checked_add(file.scanned_len)
            .and_then(|size| size.checked_add(ZIP64_ENTRY_FIXED_SIZE))
            .and_then(|size| size.checked_add(names_size))
            .ok_or(ZipBuildError::Limit("zip archive size overflow"))?;
    }
    Ok(archive_size)
}

pub(super) fn plan_zip<D: DirectoryAccess>(
    directory: &D,
    root_path: &str,
    settings: &RuntimeSettings,
) -> std::result::Result<ZipPlan, ZipBuildError> {
    let mut queue = VecDeque::from([(root_path.to_string(), String::new())]);
    let mut files = Vec::new();
    let mut regular_file_count = 0usize;
    let mut scanned_entries = 0usize;
    let mut total_data = 0u64;
    while let Some((current_directory, archive_prefix)) = queue.pop_front() {
        let mut scan = directory
            .scan_entries(&current_directory)
            .map_err(ZipBuildError::Source)?;
        loop {
            let remaining = settings.max_search_entries.saturating_sub(scanned_entries);
            if remaining == 0 {
                let sentinel = scan.run_batch(1).map_err(ZipBuildError::Source)?;
                if sentinel.scanned == 0 && sentinel.complete {
                    break;
                }
                return Err(ZipBuildError::Limit("zip scan entry limit exceeded"));
            }
            let batch = scan
                .run_batch(remaining.min(100))
                .map_err(ZipBuildError::Source)?;
            scanned_entries = scanned_entries.saturating_add(batch.scanned);
            for entry in batch.entries {
                let source_path = join_display(&current_directory, &entry.name);
                let archive_name = join_display(&archive_prefix, &entry.name);
                if entry.is_dir {
                    let directory_name = format!("{archive_name}/");
                    if directory_name.len() > u16::MAX as usize {
                        return Err(ZipBuildError::Limit("zip entry name is too long"));
                    }
                    files.push(ZipFilePlan {
                        source_path: source_path.clone(),
                        archive_name: directory_name,
                        scanned_len: 0,
                        is_directory: true,
                    });
                    queue.push_back((source_path, archive_name));
                    continue;
                }
                if archive_name.len() > u16::MAX as usize {
                    return Err(ZipBuildError::Limit("zip entry name is too long"));
                }
                files.push(ZipFilePlan {
                    source_path,
                    archive_name: archive_name.clone(),
                    scanned_len: entry.len,
                    is_directory: false,
                });
                regular_file_count = regular_file_count.saturating_add(1);
                if settings.max_zip_files != 0 && regular_file_count > settings.max_zip_files {
                    return Err(ZipBuildError::Limit("zip file count limit exceeded"));
                }
                total_data = total_data
                    .checked_add(entry.len)
                    .ok_or(ZipBuildError::Limit("zip size overflow"))?;
                if settings.max_zip_size != 0 && total_data > settings.max_zip_size {
                    return Err(ZipBuildError::Limit("zip size limit exceeded"));
                }
            }
            if batch.complete {
                break;
            }
        }
    }
    let estimated_archive_size = estimate_zip_archive_size(&files)?;
    Ok(ZipPlan {
        files,
        max_data_size: settings.max_zip_size,
        estimated_archive_size,
    })
}

struct CountingWriter<W> {
    inner: W,
    written: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, written: 0 }
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.written = self
            .written
            .checked_add(written as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "zip size overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(super) struct StreamingZipEntry {
    pub(super) name: String,
    pub(super) crc: u32,
    pub(super) size: u64,
    pub(super) local_offset: u64,
    pub(super) is_directory: bool,
}

fn write_zip_u16(writer: &mut impl Write, value: u16) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_zip_u32(writer: &mut impl Write, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_zip_u64(writer: &mut impl Write, value: u64) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_streaming_local_header(writer: &mut impl Write, name: &[u8]) -> io::Result<()> {
    write_zip_u32(writer, 0x0403_4b50)?;
    write_zip_u16(writer, ZIP64_VERSION)?;
    write_zip_u16(writer, 0x0808)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 33)?;
    write_zip_u32(writer, 0)?;
    write_zip_u32(writer, u32::MAX)?;
    write_zip_u32(writer, u32::MAX)?;
    write_zip_u16(writer, name.len() as u16)?;
    write_zip_u16(writer, ZIP64_LOCAL_EXTRA_SIZE as u16)?;
    writer.write_all(name)?;
    // Bit 3 makes the descriptor authoritative; zero placeholders announce its 64-bit width.
    write_zip_u16(writer, 0x0001)?;
    write_zip_u16(writer, ZIP64_SIZE_FIELDS_SIZE)?;
    write_zip_u64(writer, 0)?;
    write_zip_u64(writer, 0)?;
    Ok(())
}

fn write_streaming_descriptor(writer: &mut impl Write, crc: u32, size: u64) -> io::Result<()> {
    write_zip_u32(writer, 0x0807_4b50)?;
    write_zip_u32(writer, crc)?;
    write_zip_u64(writer, size)?;
    write_zip_u64(writer, size)
}

pub(super) fn write_streaming_central_entry(
    writer: &mut impl Write,
    entry: &StreamingZipEntry,
) -> io::Result<()> {
    let name = entry.name.as_bytes();
    write_zip_u32(writer, 0x0201_4b50)?;
    write_zip_u16(writer, ZIP64_VERSION)?;
    write_zip_u16(writer, ZIP64_VERSION)?;
    write_zip_u16(writer, 0x0808)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 33)?;
    write_zip_u32(writer, entry.crc)?;
    write_zip_u32(writer, u32::MAX)?;
    write_zip_u32(writer, u32::MAX)?;
    write_zip_u16(writer, name.len() as u16)?;
    write_zip_u16(writer, ZIP64_CENTRAL_EXTRA_SIZE as u16)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 0)?;
    write_zip_u32(writer, if entry.is_directory { 0x10 } else { 0 })?;
    write_zip_u32(writer, u32::MAX)?;
    writer.write_all(name)?;
    write_zip_u16(writer, 0x0001)?;
    write_zip_u16(writer, ZIP64_EXTRA_PAYLOAD_SIZE)?;
    write_zip_u64(writer, entry.size)?;
    write_zip_u64(writer, entry.size)?;
    write_zip_u64(writer, entry.local_offset)?;
    Ok(())
}

pub(super) fn write_streaming_eocd(writer: &mut impl Write) -> io::Result<()> {
    write_zip_u32(writer, 0x0605_4b50)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, u16::MAX)?;
    write_zip_u16(writer, u16::MAX)?;
    write_zip_u32(writer, u32::MAX)?;
    write_zip_u32(writer, u32::MAX)?;
    write_zip_u16(writer, 0)
}

pub(super) fn write_streaming_zip64_eocd(
    writer: &mut impl Write,
    entries: u64,
    central_size: u64,
    central_offset: u64,
) -> io::Result<()> {
    write_zip_u32(writer, 0x0606_4b50)?;
    write_zip_u64(writer, 44)?;
    write_zip_u16(writer, ZIP64_VERSION)?;
    write_zip_u16(writer, ZIP64_VERSION)?;
    write_zip_u32(writer, 0)?;
    write_zip_u32(writer, 0)?;
    write_zip_u64(writer, entries)?;
    write_zip_u64(writer, entries)?;
    write_zip_u64(writer, central_size)?;
    write_zip_u64(writer, central_offset)
}

pub(super) fn write_streaming_zip64_locator(
    writer: &mut impl Write,
    zip64_eocd_offset: u64,
) -> io::Result<()> {
    write_zip_u32(writer, 0x0706_4b50)?;
    write_zip_u32(writer, 0)?;
    write_zip_u64(writer, zip64_eocd_offset)?;
    write_zip_u32(writer, 1)
}

pub(super) fn write_zip_archive<D: DirectoryAccess, W: Write>(
    directory: &D,
    plan: &ZipPlan,
    output: W,
) -> std::result::Result<W, ZipBuildError> {
    let mut writer = CountingWriter::new(output);
    let mut central_entries = Vec::with_capacity(plan.files.len());
    let mut total_data = 0u64;
    let mut buffer = vec![0u8; ZIP_CHUNK_SIZE];
    for planned in &plan.files {
        let local_offset = writer.written;
        write_streaming_local_header(&mut writer, planned.archive_name.as_bytes())
            .map_err(ZipBuildError::Output)?;
        if planned.is_directory {
            write_streaming_descriptor(&mut writer, 0, 0).map_err(ZipBuildError::Output)?;
            central_entries.push(StreamingZipEntry {
                name: planned.archive_name.clone(),
                crc: 0,
                size: 0,
                local_offset,
                is_directory: true,
            });
            continue;
        }
        let mut source = directory
            .open_regular_file(&planned.source_path)
            .map_err(ZipBuildError::Source)?;
        let mut remaining = planned.scanned_len;
        let mut size = 0u64;
        let mut crc = crc32fast::Hasher::new();
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
            let read = source
                .read(&mut buffer[..wanted])
                .map_err(ZipBuildError::Source)?;
            if read == 0 {
                break;
            }
            remaining -= read as u64;
            size = size
                .checked_add(read as u64)
                .ok_or(ZipBuildError::Limit("zip size overflow"))?;
            total_data = total_data
                .checked_add(read as u64)
                .ok_or(ZipBuildError::Limit("zip size overflow"))?;
            if plan.max_data_size != 0 && total_data > plan.max_data_size {
                return Err(ZipBuildError::Limit("zip size limit exceeded"));
            }
            crc.update(&buffer[..read]);
            writer
                .write_all(&buffer[..read])
                .map_err(ZipBuildError::Output)?;
        }
        let crc = crc.finalize();
        write_streaming_descriptor(&mut writer, crc, size).map_err(ZipBuildError::Output)?;
        central_entries.push(StreamingZipEntry {
            name: planned.archive_name.clone(),
            crc,
            size,
            local_offset,
            is_directory: false,
        });
    }
    let central_offset = writer.written;
    for entry in &central_entries {
        write_streaming_central_entry(&mut writer, entry).map_err(ZipBuildError::Output)?;
    }
    let central_end = writer.written;
    let central_size = central_end
        .checked_sub(central_offset)
        .ok_or(ZipBuildError::Limit("zip central directory overflow"))?;
    let entries = u64::try_from(central_entries.len())
        .map_err(|_| ZipBuildError::Limit("zip file count overflow"))?;
    let zip64_eocd_offset = writer.written;
    write_streaming_zip64_eocd(&mut writer, entries, central_size, central_offset)
        .map_err(ZipBuildError::Output)?;
    write_streaming_zip64_locator(&mut writer, zip64_eocd_offset).map_err(ZipBuildError::Output)?;
    write_streaming_eocd(&mut writer).map_err(ZipBuildError::Output)?;
    writer.flush().map_err(ZipBuildError::Output)?;
    Ok(writer.into_inner())
}

pub(super) fn build_zip_temp<D: DirectoryAccess>(
    directory: &D,
    plan: &ZipPlan,
) -> std::result::Result<std::fs::File, ZipBuildError> {
    let file = tempfile::tempfile().map_err(ZipBuildError::Output)?;
    let mut file = write_zip_archive(directory, plan, file)?;
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(ZipBuildError::Output)?;
    Ok(file)
}

struct ZipChannelWriter {
    sender: tokio::sync::mpsc::Sender<io::Result<Bytes>>,
    buffer: Vec<u8>,
}

impl ZipChannelWriter {
    fn new(sender: tokio::sync::mpsc::Sender<io::Result<Bytes>>) -> Self {
        Self {
            sender,
            buffer: Vec::with_capacity(ZIP_CHUNK_SIZE),
        }
    }

    fn send_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let bytes = Bytes::from(std::mem::replace(
            &mut self.buffer,
            Vec::with_capacity(ZIP_CHUNK_SIZE),
        ));
        self.sender
            .blocking_send(Ok(bytes))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "zip client disconnected"))
    }
}

impl Write for ZipChannelWriter {
    fn write(&mut self, mut input: &[u8]) -> io::Result<usize> {
        let original_len = input.len();
        while !input.is_empty() {
            let remaining = ZIP_CHUNK_SIZE - self.buffer.len();
            let take = remaining.min(input.len());
            self.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.buffer.len() == ZIP_CHUNK_SIZE {
                self.send_buffer()?;
            }
        }
        Ok(original_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_buffer()
    }
}

#[cfg(test)]
pub(super) fn direct_zip_stream<D: DirectoryAccess>(
    directory: D,
    plan: ZipPlan,
) -> impl Stream<Item = io::Result<Bytes>> + Send {
    direct_zip_stream_with_resources(directory, plan, (), || {})
}

/// Keeps `resources` inside the producer itself. If the HTTP body is dropped,
/// the receiver closes immediately, but admission resources are not released
/// until the blocking writer observes that closure and actually terminates.
pub(super) fn direct_zip_stream_with_resources<D, R, F>(
    directory: D,
    plan: ZipPlan,
    resources: R,
    on_start: F,
) -> impl Stream<Item = io::Result<Bytes>> + Send
where
    D: DirectoryAccess,
    R: Send + 'static,
    F: FnOnce() + Send + 'static,
{
    let (sender, receiver) = tokio::sync::mpsc::channel(ZIP_CHANNEL_CHUNKS);
    let error_sender = sender.clone();
    tokio::task::spawn_blocking(move || {
        let _resources = resources;
        on_start();
        if let Err(error) = write_zip_archive(&directory, &plan, ZipChannelWriter::new(sender)) {
            let _ = error_sender.blocking_send(Err(error.into_io()));
        }
    });
    futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    })
}

pub(super) struct ReservedZipStream {
    pub(super) inner: ReaderStream<tokio::fs::File>,
    pub(super) _reservation: ZipTempReservation,
}

impl Stream for ReservedZipStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(context)
    }
}

pub(super) fn zip_error(error: &ZipBuildError) -> AppError {
    match error {
        ZipBuildError::Limit(_) => AppError(StatusCode::PAYLOAD_TOO_LARGE, "ZIP-Limit erreicht"),
        ZipBuildError::Source(_) => AppError(StatusCode::NOT_FOUND, "ZIP-Quelle nicht verfügbar"),
        ZipBuildError::Output(_) => AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ZIP-Erstellung fehlgeschlagen",
        ),
    }
}

pub(super) enum PreviewContent {
    TooLarge { size: u64 },
    Text(String),
    Media { kind: PreviewKind, size: u64 },
}

#[cfg(test)]
pub(super) struct TextPreviewReadTestHook {
    pub(super) path: String,
    pub(super) entered: std::sync::atomic::AtomicUsize,
    pub(super) released: std::sync::Mutex<bool>,
    pub(super) wake: std::sync::Condvar,
}

#[cfg(test)]
impl TextPreviewReadTestHook {
    pub(super) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}

#[cfg(test)]
pub(super) struct TextPreviewReadTestGuard(pub(super) Arc<TextPreviewReadTestHook>);

#[cfg(test)]
impl Drop for TextPreviewReadTestGuard {
    fn drop(&mut self) {
        self.0.release();
        let mut slot = TEXT_PREVIEW_READ_TEST_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap();
        if slot
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, &self.0))
        {
            *slot = None;
        }
    }
}

#[cfg(test)]
pub(super) static TEXT_PREVIEW_READ_TEST_HOOK: OnceLock<
    std::sync::Mutex<Option<Arc<TextPreviewReadTestHook>>>,
> = OnceLock::new();

#[cfg(test)]
fn block_text_preview_read_for_test(path: &str) {
    let hook = TEXT_PREVIEW_READ_TEST_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap()
        .clone();
    let Some(hook) = hook.filter(|hook| hook.path == path) else {
        return;
    };
    hook.entered.fetch_add(1, Ordering::AcqRel);
    let mut released = hook.released.lock().unwrap();
    while !*released {
        released = hook.wake.wait(released).unwrap();
    }
}

pub(super) fn read_preview<D: DirectoryAccess>(
    secure_root: &D,
    path: &str,
    settings: &RuntimeSettings,
) -> std::io::Result<PreviewContent> {
    let metadata = secure_root.entry_metadata(path)?;
    let file = secure_root.open_regular_file(path)?;
    read_preview_opened(file, &metadata, path, settings)
}

pub(super) fn read_preview_secure_file(
    file: SecureFile,
    path: &str,
    settings: &RuntimeSettings,
) -> std::io::Result<PreviewContent> {
    let metadata = file.metadata()?;
    read_preview_opened(file.into_file(), &metadata, path, settings)
}

pub(super) fn read_preview_opened(
    file: std::fs::File,
    metadata: &std::fs::Metadata,
    path: &str,
    settings: &RuntimeSettings,
) -> std::io::Result<PreviewContent> {
    let kind = preview_kind(path, settings).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "preview extension is not allowed",
        )
    })?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "preview target is not a file",
        ));
    }
    if kind.is_media() {
        if metadata.len() > settings.max_media_preview_size {
            return Ok(PreviewContent::TooLarge {
                size: metadata.len(),
            });
        }
        return Ok(PreviewContent::Media {
            kind,
            size: metadata.len(),
        });
    }
    if metadata.len() > settings.max_preview_size {
        return Ok(PreviewContent::TooLarge {
            size: metadata.len(),
        });
    }
    #[cfg(test)]
    block_text_preview_read_for_test(path);
    let read_limit = settings.max_preview_size.checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "preview size limit is too large",
        )
    })?;
    let allocation = usize::try_from(read_limit).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "preview size does not fit in memory",
        )
    })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(allocation)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut file = file.take(read_limit);
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    if bytes.len() as u64 > settings.max_preview_size {
        return Ok(PreviewContent::TooLarge {
            size: metadata.len().max(bytes.len() as u64),
        });
    }
    if bytes.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "binary content is not previewed",
        ));
    }
    let text = String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "text preview is not valid UTF-8",
        )
    })?;
    Ok(PreviewContent::Text(text))
}

pub(super) async fn raw_preview_response<D: DirectoryAccess>(
    secure_root: D,
    method: Method,
    headers: HeaderMap,
    relative_file: String,
    kind: PreviewKind,
    max_size: u64,
) -> Result<Response> {
    let open_path = relative_file.clone();
    let file = tokio::task::spawn_blocking(move || secure_root.open_regular_file(&open_path))
        .await
        .map_err(internal)?
        .map_err(|_| AppError(StatusCode::NOT_FOUND, "Datei nicht verfügbar"))?;
    raw_preview_opened_response(file, method, headers, relative_file, kind, max_size).await
}

pub(super) async fn raw_preview_secure_file_response(
    file: SecureFile,
    method: Method,
    headers: HeaderMap,
    relative_file: String,
    kind: PreviewKind,
    max_size: u64,
) -> Result<Response> {
    raw_preview_opened_response(
        file.into_file(),
        method,
        headers,
        relative_file,
        kind,
        max_size,
    )
    .await
}

async fn raw_preview_opened_response(
    file: std::fs::File,
    method: Method,
    headers: HeaderMap,
    relative_file: String,
    kind: PreviewKind,
    max_size: u64,
) -> Result<Response> {
    if !file.metadata().map_err(internal)?.is_file() {
        return Err(AppError(StatusCode::BAD_REQUEST, "Keine Datei"));
    }
    let mut f = tokio::fs::File::from_std(file);
    let length = f.metadata().await.map_err(internal)?.len();
    if length > max_size {
        return Err(AppError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Vorschau-Limit erreicht",
        ));
    }
    let range = match headers.get(header::RANGE) {
        Some(value) => match value
            .to_str()
            .ok()
            .and_then(|value| parse_byte_range(value, length).ok())
        {
            Some(range) => Some(range),
            None => {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                response
                    .headers_mut()
                    .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{length}")).map_err(internal)?,
                );
                return Ok(response);
            }
        },
        None => None,
    };
    let (start, end) = range.unwrap_or((0, length.saturating_sub(1)));
    let response_length = if length == 0 { 0 } else { end - start + 1 };
    if start > 0 {
        f.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(internal)?;
    }
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from_stream(ReaderStream::new(f.take(response_length)))
    };
    let mut r = Response::new(body);
    if range.is_some() {
        *r.status_mut() = StatusCode::PARTIAL_CONTENT;
        r.headers_mut().insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{end}/{length}")).map_err(internal)?,
        );
    }
    let name = Path::new(&relative_file)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("preview");
    let filename = percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC);
    r.headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    r.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&response_length.to_string()).map_err(internal)?,
    );
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(kind.content_type()),
    );
    r.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("inline; filename*=UTF-8''{filename}")).map_err(internal)?,
    );
    r.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Ok(r)
}
