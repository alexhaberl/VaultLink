use std::{
    borrow::Borrow,
    collections::VecDeque,
    io::{self, Read, Seek, Write},
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::Stream;
use tokio_util::io::ReaderStream;

use crate::{
    path_security::safe_filename,
    runtime::RuntimeSettings,
    secure_fs::{DirectoryScan, SecureDirectory, SecureFile, SecureRoot},
    services::upload::storage_full_error,
    AppState,
};

use super::BUFFERED_RESPONSE_CHUNK_BYTES;

const ZIP_CHANNEL_CHUNKS: usize = 8;
const ZIP_TEMP_MIN_RESERVE: u64 = 64 * 1024 * 1024;
const ZIP_DIRECT_ARCHIVE_THRESHOLD: u64 = 64 * 1024 * 1024;
const ZIP_DIRECT_ENTRY_THRESHOLD: usize = 1_000;
pub(crate) const ZIP_PLAN_MAX_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const ZIP64_VERSION: u16 = 45;
const ZIP_LOCAL_HEADER_SIZE: u64 = 30;
const ZIP_CENTRAL_HEADER_SIZE: u64 = 46;
const ZIP64_DATA_DESCRIPTOR_SIZE: u64 = 24;
pub(crate) const ZIP64_LOCAL_EXTRA_SIZE: u64 = 20;
pub(crate) const ZIP64_CENTRAL_EXTRA_SIZE: u64 = 28;
pub(crate) const ZIP64_EXTRA_PAYLOAD_SIZE: u16 = 24;
pub(crate) const ZIP64_SIZE_FIELDS_SIZE: u16 = 16;
pub(crate) const ZIP_EOCD_SIZE: u64 = 22;
const ZIP64_END_RECORDS_SIZE: u64 = 76;
const ZIP64_ENTRY_FIXED_SIZE: u64 = ZIP_LOCAL_HEADER_SIZE
    + ZIP64_LOCAL_EXTRA_SIZE
    + ZIP64_DATA_DESCRIPTOR_SIZE
    + ZIP_CENTRAL_HEADER_SIZE
    + ZIP64_CENTRAL_EXTRA_SIZE;
const ZIP64_ARCHIVE_END_SIZE: u64 = ZIP_EOCD_SIZE + ZIP64_END_RECORDS_SIZE;
static ZIP_TEMP_RESERVED: AtomicU64 = AtomicU64::new(0);

pub(crate) trait DirectoryAccess: Clone + Send + 'static {
    fn scan_entries(&self, relative: &str) -> io::Result<DirectoryScan>;
    fn open_regular_file(&self, relative: &str) -> io::Result<std::fs::File>;
    fn entry_metadata(&self, relative: &str) -> io::Result<std::fs::Metadata>;
}

impl DirectoryAccess for SecureRoot {
    fn scan_entries(&self, relative: &str) -> io::Result<DirectoryScan> {
        self.scan_directory(relative)
    }

    fn open_regular_file(&self, relative: &str) -> io::Result<std::fs::File> {
        self.open_file(relative)
    }

    fn entry_metadata(&self, relative: &str) -> io::Result<std::fs::Metadata> {
        self.metadata(relative)
    }
}

impl DirectoryAccess for SecureDirectory {
    fn scan_entries(&self, relative: &str) -> io::Result<DirectoryScan> {
        self.scan_directory(relative)
    }

    fn open_regular_file(&self, relative: &str) -> io::Result<std::fs::File> {
        self.open_file(relative).map(SecureFile::into_file)
    }

    fn entry_metadata(&self, relative: &str) -> io::Result<std::fs::Metadata> {
        self.metadata(relative)
    }
}

pub(crate) struct ZipTempReservation {
    bytes: u64,
}

impl ZipTempReservation {
    pub(crate) async fn acquire(
        state: &(impl Borrow<AppState> + ?Sized),
        estimated_bytes: u64,
    ) -> io::Result<Option<Self>> {
        let state = state.borrow();
        let safety = ZIP_TEMP_MIN_RESERVE.max(estimated_bytes / 10);
        let Some(required) = estimated_bytes.checked_add(safety) else {
            return Ok(None);
        };
        let available = match state.disk_stats_cache().get(&std::env::temp_dir()).await {
            Ok(stats) => stats.free,
            Err(error) if error.kind() == io::ErrorKind::TimedOut => return Ok(None),
            Err(error) => return Err(error),
        };
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
    pub(crate) fn acquire_unchecked_for_test(estimated_bytes: u64) -> Self {
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
pub(crate) fn zip_temp_reserved_bytes_for_test() -> u64 {
    ZIP_TEMP_RESERVED.load(Ordering::Acquire)
}

#[derive(Debug)]
pub(crate) enum ZipBuildError {
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

    pub(crate) fn is_output_capacity_error(&self) -> bool {
        matches!(self, Self::Output(error) if storage_full_error(error))
    }
}

pub(crate) struct ZipFilePlan {
    pub(crate) source_path: Box<str>,
    pub(crate) archive_name: Box<str>,
    pub(crate) scanned_len: u64,
    pub(crate) is_directory: bool,
}

pub(crate) struct ZipPlan {
    pub(crate) files: Vec<ZipFilePlan>,
    pub(crate) max_data_size: u64,
    pub(crate) estimated_archive_size: u64,
}

impl ZipPlan {
    pub(crate) fn requires_direct_stream(&self) -> bool {
        zip_requires_direct_stream(self.estimated_archive_size, self.files.len())
    }
}

pub(crate) fn zip_requires_direct_stream(estimated_archive_size: u64, entry_count: usize) -> bool {
    estimated_archive_size >= ZIP_DIRECT_ARCHIVE_THRESHOLD
        || entry_count >= ZIP_DIRECT_ENTRY_THRESHOLD
}

#[cfg(test)]
pub(crate) fn checked_zip_plan_memory(
    used: usize,
    source_path_bytes: usize,
    archive_name_bytes: usize,
) -> Result<usize, ZipBuildError> {
    let entry_bytes = std::mem::size_of::<ZipFilePlan>()
        .checked_add(source_path_bytes)
        .and_then(|bytes| bytes.checked_add(archive_name_bytes))
        .ok_or(ZipBuildError::Limit("zip plan memory limit exceeded"))?;
    used.checked_add(entry_bytes)
        .filter(|bytes| *bytes <= ZIP_PLAN_MAX_BYTES)
        .ok_or(ZipBuildError::Limit("zip plan memory limit exceeded"))
}

type PendingZipDirectory = (Box<str>, Box<str>);

struct ZipPlanMemory {
    used: usize,
}

impl ZipPlanMemory {
    fn new(
        files: &Vec<ZipFilePlan>,
        queue: &VecDeque<PendingZipDirectory>,
    ) -> Result<Self, ZipBuildError> {
        let used = std::mem::size_of::<ZipPlan>()
            .checked_add(
                files
                    .capacity()
                    .checked_mul(std::mem::size_of::<ZipFilePlan>())
                    .ok_or(ZipBuildError::Limit("zip plan memory limit exceeded"))?,
            )
            .and_then(|used| {
                queue
                    .capacity()
                    .checked_mul(std::mem::size_of::<PendingZipDirectory>())
                    .and_then(|queue_bytes| used.checked_add(queue_bytes))
            })
            .and_then(|used| {
                queue.iter().try_fold(used, |used, (source, archive)| {
                    used.checked_add(source.len())?.checked_add(archive.len())
                })
            })
            .filter(|used| *used <= ZIP_PLAN_MAX_BYTES)
            .ok_or(ZipBuildError::Limit("zip plan memory limit exceeded"))?;
        Ok(Self { used })
    }

    fn retain_bytes(&mut self, bytes: usize) -> Result<(), ZipBuildError> {
        self.used = self
            .used
            .checked_add(bytes)
            .filter(|used| *used <= ZIP_PLAN_MAX_BYTES)
            .ok_or(ZipBuildError::Limit("zip plan memory limit exceeded"))?;
        Ok(())
    }

    fn release_bytes(&mut self, bytes: usize) {
        self.used = self
            .used
            .checked_sub(bytes)
            .expect("ZIP plan memory accounting underflow");
    }

    fn reserve_file(&mut self, files: &mut Vec<ZipFilePlan>) -> Result<(), ZipBuildError> {
        let old_capacity = files.capacity();
        files
            .try_reserve_exact(1)
            .map_err(|_| ZipBuildError::Limit("zip plan memory limit exceeded"))?;
        let additional_capacity = files.capacity().saturating_sub(old_capacity);
        self.retain_bytes(
            additional_capacity
                .checked_mul(std::mem::size_of::<ZipFilePlan>())
                .ok_or(ZipBuildError::Limit("zip plan memory limit exceeded"))?,
        )
    }

    fn reserve_directory(
        &mut self,
        queue: &mut VecDeque<PendingZipDirectory>,
    ) -> Result<(), ZipBuildError> {
        let old_capacity = queue.capacity();
        queue
            .try_reserve_exact(1)
            .map_err(|_| ZipBuildError::Limit("zip plan memory limit exceeded"))?;
        let additional_capacity = queue.capacity().saturating_sub(old_capacity);
        self.retain_bytes(
            additional_capacity
                .checked_mul(std::mem::size_of::<PendingZipDirectory>())
                .ok_or(ZipBuildError::Limit("zip plan memory limit exceeded"))?,
        )
    }
}

pub(crate) fn estimate_zip_archive_size(files: &[ZipFilePlan]) -> Result<u64, ZipBuildError> {
    files.iter().try_fold(ZIP64_ARCHIVE_END_SIZE, |size, file| {
        let name_len = u64::try_from(file.archive_name.len())
            .map_err(|_| ZipBuildError::Limit("zip entry name is too long"))?;
        size.checked_add(file.scanned_len)
            .and_then(|size| size.checked_add(ZIP64_ENTRY_FIXED_SIZE))
            .and_then(|size| size.checked_add(name_len.checked_mul(2)?))
            .ok_or(ZipBuildError::Limit("zip archive size overflow"))
    })
}

pub(crate) fn plan_zip<D: DirectoryAccess>(
    directory: &D,
    root_path: &str,
    settings: &RuntimeSettings,
) -> Result<ZipPlan, ZipBuildError> {
    let mut queue = VecDeque::new();
    queue
        .try_reserve_exact(1)
        .map_err(|_| ZipBuildError::Limit("zip plan memory limit exceeded"))?;
    queue.push_back((root_path.into(), "".into()));
    let mut files = Vec::new();
    let mut plan_memory = ZipPlanMemory::new(&files, &queue)?;
    let mut regular_file_count = 0usize;
    let mut scanned_entries = 0usize;
    let mut total_data = 0u64;
    while let Some((current_directory, archive_prefix)) = queue.pop_front() {
        let active_directory_bytes = current_directory
            .len()
            .checked_add(archive_prefix.len())
            .ok_or(ZipBuildError::Limit("zip plan memory limit exceeded"))?;
        scan_zip_directory(
            directory,
            settings,
            &mut queue,
            &mut files,
            &mut plan_memory,
            &mut regular_file_count,
            &mut scanned_entries,
            &mut total_data,
            &current_directory,
            &archive_prefix,
        )?;
        plan_memory.release_bytes(active_directory_bytes);
    }
    let estimated_archive_size = estimate_zip_archive_size(&files)?;
    Ok(ZipPlan {
        files,
        max_data_size: settings.max_zip_size,
        estimated_archive_size,
    })
}

#[allow(clippy::too_many_arguments)]
fn scan_zip_directory<D: DirectoryAccess>(
    directory: &D,
    settings: &RuntimeSettings,
    queue: &mut VecDeque<PendingZipDirectory>,
    files: &mut Vec<ZipFilePlan>,
    plan_memory: &mut ZipPlanMemory,
    regular_file_count: &mut usize,
    scanned_entries: &mut usize,
    total_data: &mut u64,
    current_directory: &str,
    archive_prefix: &str,
) -> Result<(), ZipBuildError> {
    let mut scan = directory
        .scan_entries(current_directory)
        .map_err(ZipBuildError::Source)?;
    loop {
        let remaining = settings.max_search_entries.saturating_sub(*scanned_entries);
        if remaining == 0 {
            let sentinel = scan.run_batch(1).map_err(ZipBuildError::Source)?;
            if sentinel.scanned == 0 && sentinel.complete {
                return Ok(());
            }
            return Err(ZipBuildError::Limit("zip scan entry limit exceeded"));
        }
        let batch = scan
            .run_batch(remaining.min(100))
            .map_err(ZipBuildError::Source)?;
        *scanned_entries = scanned_entries.saturating_add(batch.scanned);
        for entry in batch.entries {
            add_zip_entry(
                settings,
                queue,
                files,
                plan_memory,
                regular_file_count,
                total_data,
                current_directory,
                archive_prefix,
                &entry,
            )?;
        }
        if batch.complete {
            return Ok(());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_zip_entry(
    settings: &RuntimeSettings,
    queue: &mut VecDeque<PendingZipDirectory>,
    files: &mut Vec<ZipFilePlan>,
    plan_memory: &mut ZipPlanMemory,
    regular_file_count: &mut usize,
    total_data: &mut u64,
    current_directory: &str,
    archive_prefix: &str,
    entry: &crate::secure_fs::Entry,
) -> Result<(), ZipBuildError> {
    safe_filename(&entry.name).map_err(|_| {
        ZipBuildError::Source(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsafe ZIP entry name",
        ))
    })?;
    let source_path: Box<str> = join_display(current_directory, &entry.name).into();
    let archive_name: Box<str> = join_display(archive_prefix, &entry.name).into();
    if entry.is_dir {
        let directory_name: Box<str> = format!("{archive_name}/").into();
        validate_zip_name(&directory_name)?;
        plan_memory.reserve_file(files)?;
        plan_memory.reserve_directory(queue)?;
        let retained_string_bytes = source_path
            .len()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(archive_name.len()))
            .and_then(|bytes| bytes.checked_add(directory_name.len()))
            .ok_or(ZipBuildError::Limit("zip plan memory limit exceeded"))?;
        plan_memory.retain_bytes(retained_string_bytes)?;
        files.push(ZipFilePlan {
            source_path: source_path.clone(),
            archive_name: directory_name,
            scanned_len: 0,
            is_directory: true,
        });
        queue.push_back((source_path, archive_name));
        return Ok(());
    }
    validate_zip_name(&archive_name)?;
    plan_memory.reserve_file(files)?;
    plan_memory.retain_bytes(
        source_path
            .len()
            .checked_add(archive_name.len())
            .ok_or(ZipBuildError::Limit("zip plan memory limit exceeded"))?,
    )?;
    files.push(ZipFilePlan {
        source_path,
        archive_name,
        scanned_len: entry.len,
        is_directory: false,
    });
    *regular_file_count = regular_file_count.saturating_add(1);
    if settings.max_zip_files != 0 && *regular_file_count > settings.max_zip_files {
        return Err(ZipBuildError::Limit("zip file count limit exceeded"));
    }
    *total_data = total_data
        .checked_add(entry.len)
        .ok_or(ZipBuildError::Limit("zip size overflow"))?;
    if settings.max_zip_size != 0 && *total_data > settings.max_zip_size {
        return Err(ZipBuildError::Limit("zip size limit exceeded"));
    }
    Ok(())
}

fn validate_zip_name(name: &str) -> Result<(), ZipBuildError> {
    if name.len() > u16::MAX as usize {
        Err(ZipBuildError::Limit("zip entry name is too long"))
    } else {
        Ok(())
    }
}

fn join_display(base: &str, child: &str) -> String {
    if base.is_empty() || base == "." {
        child.to_owned()
    } else {
        format!("{base}/{child}")
    }
}

struct CountingWriter<W> {
    inner: W,
    written: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, written: 0 }
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

pub(crate) struct StreamingZipEntry<'a> {
    pub(crate) name: &'a str,
    pub(crate) crc: u32,
    pub(crate) size: u64,
    pub(crate) local_offset: u64,
    pub(crate) is_directory: bool,
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
    write_zip_u16(writer, 0x0001)?;
    write_zip_u16(writer, ZIP64_SIZE_FIELDS_SIZE)?;
    write_zip_u64(writer, 0)?;
    write_zip_u64(writer, 0)
}

fn write_streaming_descriptor(writer: &mut impl Write, crc: u32, size: u64) -> io::Result<()> {
    write_zip_u32(writer, 0x0807_4b50)?;
    write_zip_u32(writer, crc)?;
    write_zip_u64(writer, size)?;
    write_zip_u64(writer, size)
}

pub(crate) fn write_streaming_central_entry(
    writer: &mut impl Write,
    entry: &StreamingZipEntry<'_>,
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
    write_zip_u64(writer, entry.local_offset)
}

pub(crate) fn write_streaming_eocd(writer: &mut impl Write) -> io::Result<()> {
    write_zip_u32(writer, 0x0605_4b50)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, 0)?;
    write_zip_u16(writer, u16::MAX)?;
    write_zip_u16(writer, u16::MAX)?;
    write_zip_u32(writer, u32::MAX)?;
    write_zip_u32(writer, u32::MAX)?;
    write_zip_u16(writer, 0)
}

pub(crate) fn write_streaming_zip64_eocd(
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

pub(crate) fn write_streaming_zip64_locator(
    writer: &mut impl Write,
    zip64_eocd_offset: u64,
) -> io::Result<()> {
    write_zip_u32(writer, 0x0706_4b50)?;
    write_zip_u32(writer, 0)?;
    write_zip_u64(writer, zip64_eocd_offset)?;
    write_zip_u32(writer, 1)
}

pub(crate) fn write_zip_archive<D: DirectoryAccess, W: Write>(
    directory: &D,
    plan: &ZipPlan,
    output: W,
) -> Result<W, ZipBuildError> {
    let mut writer = CountingWriter::new(output);
    let mut central_entries = Vec::with_capacity(plan.files.len());
    let mut total_data = 0u64;
    let mut buffer = vec![0u8; BUFFERED_RESPONSE_CHUNK_BYTES];
    for planned in &plan.files {
        write_zip_file(
            directory,
            plan,
            planned,
            &mut writer,
            &mut central_entries,
            &mut total_data,
            &mut buffer,
        )?;
    }
    finish_zip(&mut writer, &central_entries)?;
    writer.flush().map_err(ZipBuildError::Output)?;
    Ok(writer.inner)
}

fn write_zip_file<'a, D: DirectoryAccess, W: Write>(
    directory: &D,
    plan: &ZipPlan,
    planned: &'a ZipFilePlan,
    writer: &mut CountingWriter<W>,
    central_entries: &mut Vec<StreamingZipEntry<'a>>,
    total_data: &mut u64,
    buffer: &mut [u8],
) -> Result<(), ZipBuildError> {
    let local_offset = writer.written;
    write_streaming_local_header(writer, planned.archive_name.as_bytes())
        .map_err(ZipBuildError::Output)?;
    if planned.is_directory {
        write_streaming_descriptor(writer, 0, 0).map_err(ZipBuildError::Output)?;
        central_entries.push(StreamingZipEntry {
            name: &planned.archive_name,
            crc: 0,
            size: 0,
            local_offset,
            is_directory: true,
        });
        return Ok(());
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
        size = checked_zip_data(size, read as u64, 0)?;
        *total_data = checked_zip_data(*total_data, read as u64, plan.max_data_size)?;
        crc.update(&buffer[..read]);
        writer
            .write_all(&buffer[..read])
            .map_err(ZipBuildError::Output)?;
    }
    let crc = crc.finalize();
    write_streaming_descriptor(writer, crc, size).map_err(ZipBuildError::Output)?;
    central_entries.push(StreamingZipEntry {
        name: &planned.archive_name,
        crc,
        size,
        local_offset,
        is_directory: false,
    });
    Ok(())
}

fn checked_zip_data(current: u64, added: u64, maximum: u64) -> Result<u64, ZipBuildError> {
    let total = current
        .checked_add(added)
        .ok_or(ZipBuildError::Limit("zip size overflow"))?;
    if maximum != 0 && total > maximum {
        Err(ZipBuildError::Limit("zip size limit exceeded"))
    } else {
        Ok(total)
    }
}

fn finish_zip(
    writer: &mut CountingWriter<impl Write>,
    central_entries: &[StreamingZipEntry<'_>],
) -> Result<(), ZipBuildError> {
    let central_offset = writer.written;
    for entry in central_entries {
        write_streaming_central_entry(writer, entry).map_err(ZipBuildError::Output)?;
    }
    let central_size = writer
        .written
        .checked_sub(central_offset)
        .ok_or(ZipBuildError::Limit("zip central directory overflow"))?;
    let entries = u64::try_from(central_entries.len())
        .map_err(|_| ZipBuildError::Limit("zip file count overflow"))?;
    let zip64_eocd_offset = writer.written;
    write_streaming_zip64_eocd(writer, entries, central_size, central_offset)
        .map_err(ZipBuildError::Output)?;
    write_streaming_zip64_locator(writer, zip64_eocd_offset).map_err(ZipBuildError::Output)?;
    write_streaming_eocd(writer).map_err(ZipBuildError::Output)
}

pub(crate) fn build_zip_temp<D: DirectoryAccess>(
    directory: &D,
    plan: &ZipPlan,
) -> Result<std::fs::File, ZipBuildError> {
    let file = tempfile::tempfile().map_err(ZipBuildError::Output)?;
    let mut file = write_zip_archive(directory, plan, file)?;
    file.seek(io::SeekFrom::Start(0))
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
            buffer: Vec::with_capacity(BUFFERED_RESPONSE_CHUNK_BYTES),
        }
    }

    fn send_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let bytes = Bytes::from(std::mem::replace(
            &mut self.buffer,
            Vec::with_capacity(BUFFERED_RESPONSE_CHUNK_BYTES),
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
            let remaining = BUFFERED_RESPONSE_CHUNK_BYTES - self.buffer.len();
            let take = remaining.min(input.len());
            self.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.buffer.len() == BUFFERED_RESPONSE_CHUNK_BYTES {
                self.send_buffer()?;
            }
        }
        Ok(original_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_buffer()
    }
}

pub(crate) fn direct_zip_stream_with_resources<D, R, F>(
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

#[cfg(test)]
pub(crate) fn direct_zip_stream<D>(
    directory: D,
    plan: ZipPlan,
) -> impl Stream<Item = io::Result<Bytes>> + Send
where
    D: DirectoryAccess,
{
    direct_zip_stream_with_resources(directory, plan, (), || {})
}

pub(crate) struct ReservedZipStream {
    pub(crate) inner: ReaderStream<tokio::fs::File>,
    pub(crate) _reservation: ZipTempReservation,
}

impl Stream for ReservedZipStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(context)
    }
}

#[cfg(test)]
mod plan_memory_tests {
    use super::*;

    #[test]
    fn accounting_includes_vector_queue_capacity_and_pending_paths() {
        let files = Vec::<ZipFilePlan>::with_capacity(3);
        let mut queue = VecDeque::<PendingZipDirectory>::with_capacity(2);
        queue.push_back(("source/path".into(), "archive/path".into()));

        let mut memory = ZipPlanMemory::new(&files, &queue).unwrap();
        let expected = std::mem::size_of::<ZipPlan>()
            + files.capacity() * std::mem::size_of::<ZipFilePlan>()
            + queue.capacity() * std::mem::size_of::<PendingZipDirectory>()
            + "source/path".len()
            + "archive/path".len();
        assert_eq!(memory.used, expected);

        let active = queue.pop_front().unwrap();
        memory.release_bytes(active.0.len() + active.1.len());
        assert_eq!(
            memory.used,
            expected - "source/path".len() - "archive/path".len()
        );
    }

    #[test]
    fn accounting_rejects_every_byte_above_the_hard_ceiling() {
        let mut memory = ZipPlanMemory {
            used: ZIP_PLAN_MAX_BYTES,
        };
        assert!(matches!(
            memory.retain_bytes(1),
            Err(ZipBuildError::Limit("zip plan memory limit exceeded"))
        ));
    }
}
