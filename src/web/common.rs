use std::{
    cmp::Ordering,
    collections::{BinaryHeap, VecDeque},
    io,
    time::{Instant, UNIX_EPOCH},
};

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    rendering::{GB, MB},
    AppError, Result,
};
use crate::{
    directory_cache::{
        DirectoryEntrySortKey, DirectoryEntrySortPrimary, DirectorySnapshot,
        DirectorySnapshotBuilder,
    },
    i18n::{self, Locale},
    internal_reporting::{report_internal, InternalOperation},
    log_safety::EscapedLogPath,
    policy::{self, PreviewKind},
    runtime,
    runtime::RuntimeSettings,
    secure_fs::{DirectoryScan, Entry, SecureDirectory, SecureFile, SecureRoot},
    sensitive::SecretString,
    webauthn::WebAuthnServiceError,
};

pub(super) fn webauthn_start_response<T: Serialize>(
    result: std::result::Result<T, WebAuthnServiceError>,
) -> Result<Response> {
    match result {
        Ok(challenge) => Ok(Json(challenge).into_response()),
        Err(WebAuthnServiceError::CapacityExceeded) => {
            let mut response = (
                StatusCode::SERVICE_UNAVAILABLE,
                "WebAuthn is temporarily busy",
            )
                .into_response();
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
            Ok(response)
        }
        Err(WebAuthnServiceError::Ceremony(_)) => Err(AppError(
            StatusCode::BAD_REQUEST,
            "Security key authentication could not be started",
        )),
    }
}

include!("common/webauthn_response_tests.rs");
include!("common/model.rs");

#[cfg(feature = "fuzzing")]
#[path = "common/fuzz.rs"]
pub(crate) mod fuzz;

fn entry_sort_key(entry: &Entry, column: FileSortColumn) -> DirectoryEntrySortKey {
    let primary = match column {
        FileSortColumn::Name => DirectoryEntrySortPrimary::Name,
        FileSortColumn::Type => DirectoryEntrySortPrimary::Type(!entry.is_dir),
        FileSortColumn::Size => DirectoryEntrySortPrimary::Size(entry.len),
        FileSortColumn::Modified => DirectoryEntrySortPrimary::Modified(entry.modified),
    };
    DirectoryEntrySortKey {
        primary,
        folded_name: entry.name.to_lowercase(),
        original_name: entry.name.clone(),
    }
}

#[derive(Debug, Eq, PartialEq)]
struct DirectedEntrySortKey {
    key: DirectoryEntrySortKey,
    direction: FileSortDirection,
}

impl DirectedEntrySortKey {
    fn new(entry: &Entry, column: FileSortColumn, direction: FileSortDirection) -> Self {
        Self {
            key: entry_sort_key(entry, column),
            direction,
        }
    }
}

impl Ord for DirectedEntrySortKey {
    fn cmp(&self, other: &Self) -> Ordering {
        directed_key_order(&self.key, &other.key, self.direction)
    }
}

impl PartialOrd for DirectedEntrySortKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn directed_key_order(
    left: &DirectoryEntrySortKey,
    right: &DirectoryEntrySortKey,
    direction: FileSortDirection,
) -> Ordering {
    let order = left.cmp(right);
    if direction == FileSortDirection::Descending {
        order.reverse()
    } else {
        order
    }
}

#[cfg(test)]
pub(super) fn sort_entries(
    entries: &mut [Entry],
    column: FileSortColumn,
    direction: FileSortDirection,
) {
    entries.sort_by_cached_key(|entry| DirectedEntrySortKey::new(entry, column, direction));
}

pub(super) fn sort_search_hits(
    hits: &mut [SearchHit],
    column: FileSortColumn,
    direction: FileSortDirection,
) {
    hits.sort_by_cached_key(|hit| DirectedEntrySortKey::new(&hit.entry, column, direction));
}

pub(super) fn human(n: u64) -> String {
    let mut value = if n >= GB {
        format!("{:.1} GB", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.1} MB", n as f64 / MB as f64)
    } else if n >= 1_000 {
        format!("{:.1} KB", n as f64 / 1_000.)
    } else {
        format!("{n} B")
    };
    if i18n::current_locale() == Locale::De {
        value = value.replace('.', ",");
    }
    value
}

pub(super) fn upload_limit_label(bytes: u64) -> String {
    human(bytes)
}

pub(super) fn display_limit_unit_floor(bytes: u64, unit: u64) -> String {
    format_unit_floor(bytes, unit)
}

pub(super) fn display_limit_unit_ceil(bytes: u64, unit: u64) -> String {
    bytes.div_ceil(unit).to_string()
}

pub(super) fn format_unit_floor(bytes: u64, unit: u64) -> String {
    (bytes / unit).to_string()
}

pub(super) fn format_unit_decimal(bytes: u64, unit: u64) -> String {
    let whole = bytes / unit;
    let remainder = bytes % unit;
    if remainder == 0 {
        return whole.to_string();
    }
    let width = unit.to_string().len() - 1;
    debug_assert_eq!(10_u64.checked_pow(width as u32), Some(unit));
    let fraction = format!("{remainder:0width$}");
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}

pub(super) fn parse_unit_to_bytes(value: &str, unit: u64, label: &'static str) -> Result<u64> {
    let parsed = value
        .trim()
        .replace(',', ".")
        .parse::<f64>()
        .map_err(|_| AppError(StatusCode::BAD_REQUEST, label))?;
    if !parsed.is_finite() || parsed <= 0.0 {
        return Err(AppError(StatusCode::BAD_REQUEST, label));
    }
    let bytes = (parsed * unit as f64).round();
    if bytes < 1.0 || bytes > u64::MAX as f64 {
        return Err(AppError(StatusCode::BAD_REQUEST, label));
    }
    Ok(bytes as u64)
}

pub(super) fn parse_expiry(
    local: Option<&str>,
    offset_minutes: Option<&str>,
) -> Result<Option<DateTime<Utc>>> {
    if let Some(value) = local.map(str::trim).filter(|value| !value.is_empty()) {
        let naive = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M")
            .or_else(|_| NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S"))
            .or_else(|_| NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M"))
            .or_else(|_| NaiveDateTime::parse_from_str(value, "%d.%m.%Y %H:%M"))
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid expiration date"))?;
        let offset = offset_minutes
            .unwrap_or("0")
            .trim()
            .parse::<i64>()
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Invalid expiration date"))?;
        if !(-1_440..=1_440).contains(&offset) {
            return Err(AppError(StatusCode::BAD_REQUEST, "Invalid expiration date"));
        }
        let utc_naive = naive
            .checked_add_signed(Duration::minutes(offset))
            .ok_or(AppError(StatusCode::BAD_REQUEST, "Invalid expiration date"))?;
        return Ok(Some(DateTime::<Utc>::from_naive_utc_and_offset(
            utc_naive, Utc,
        )));
    }
    Ok(None)
}

pub(super) fn extension_is_blocked(name: &str, blocked: &[String]) -> bool {
    runtime::extension_is_blocked(name, blocked)
}

#[cfg(test)]
pub(super) fn add_upload_bytes(total: u64, chunk: usize, maximum: u64) -> Option<u64> {
    policy::add_upload_bytes(total, chunk as u64, maximum).ok()
}

pub(super) fn encoded(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

pub(super) fn otpauth_url(username: &str, secret: &str) -> SecretString {
    SecretString::new(format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}",
        encoded("VaultLink"),
        encoded(username),
        encoded(secret),
        encoded("VaultLink")
    ))
}

pub(super) fn qr_svg(data: &str) -> Result<super::templates::TrustedMarkup> {
    super::templates::TrustedMarkup::generated_qr(data).map_err(|error| {
        AppError::from(report_internal(InternalOperation::WebCommonQrRender, error))
    })
}

pub(super) fn join_display(base: &str, child: &str) -> String {
    if base.is_empty() || base == "." {
        child.to_string()
    } else {
        format!("{base}/{child}")
    }
}

pub(super) fn parent_path(path: &str) -> Option<String> {
    let clean = path.trim_matches('/');
    if clean.is_empty() {
        return None;
    }
    clean
        .rsplit_once('/')
        .map(|(parent, _)| parent.to_string())
        .or_else(|| Some(String::new()))
}

pub(super) fn preview_kind(path: &str, settings: &RuntimeSettings) -> Option<PreviewKind> {
    policy::preview_kind(path, settings)
}

pub(super) fn preview_allowed(path: &str, settings: &RuntimeSettings) -> bool {
    policy::preview_allowed(path, settings)
}

pub(super) fn public_preview_error(error: &io::Error) -> AppError {
    // Linux openat2 reports EXDEV/ELOOP when resolution would cross the
    // descriptor-bound share or follow a forbidden final symlink. Keep that
    // security boundary indistinguishable from a missing public file.
    if matches!(error.raw_os_error(), Some(18 | 40)) {
        return AppError(StatusCode::NOT_FOUND, "File unavailable");
    }
    match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => {
            AppError(StatusCode::NOT_FOUND, "File unavailable")
        }
        _ => AppError(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Preview not allowed"),
    }
}

#[derive(Debug)]
pub(super) struct SearchHit {
    pub(super) relative_path: String,
    pub(super) entry: Entry,
}

pub(super) trait DirectoryAccess: Clone + Send + 'static {
    fn scan_entries(&self, relative: &str) -> io::Result<DirectoryScan>;
    fn open_regular_file(&self, relative: &str) -> io::Result<std::fs::File>;
}

impl DirectoryAccess for SecureRoot {
    fn scan_entries(&self, relative: &str) -> io::Result<DirectoryScan> {
        self.scan_directory(relative)
    }

    fn open_regular_file(&self, relative: &str) -> io::Result<std::fs::File> {
        self.open_file(relative)
    }
}

impl DirectoryAccess for SecureDirectory {
    fn scan_entries(&self, relative: &str) -> io::Result<DirectoryScan> {
        self.scan_directory(relative)
    }

    fn open_regular_file(&self, relative: &str) -> io::Result<std::fs::File> {
        self.open_file(relative).map(SecureFile::into_file)
    }
}

#[cfg(test)]
pub(super) fn list_directory_page<D: DirectoryAccess>(
    directory: &D,
    relative: &str,
    page: usize,
    scan_limit: usize,
) -> io::Result<(Vec<Entry>, bool)> {
    let skip = page.saturating_mul(100);
    let mut visible = 0usize;
    let mut scanned = 0usize;
    let mut entries = Vec::new();
    let mut scan = directory.scan_entries(relative)?;
    while entries.len() < 101 {
        let remaining = scan_limit.saturating_sub(scanned);
        if remaining == 0 {
            let sentinel = scan.run_batch(1)?;
            return Ok((entries, sentinel.scanned != 0 || !sentinel.complete));
        }
        let batch = scan.run_batch(remaining.min(100))?;
        scanned = scanned.saturating_add(batch.scanned);
        for entry in batch.entries {
            if visible >= skip && entries.len() < 101 {
                entries.push(entry);
            }
            visible = visible.saturating_add(1);
        }
        if batch.complete {
            break;
        }
    }
    Ok((entries, false))
}

const DIRECTORY_PAGE_SIZE: usize = 100;
const DIRECTORY_CURSOR_MAX_BYTES: usize = 4_096;

#[derive(Debug, Deserialize, Serialize)]
struct DirectoryCursor {
    version: u8,
    column: FileSortColumn,
    direction: FileSortDirection,
    name: String,
    is_dir: bool,
    len: u64,
    modified_nanos: Option<u64>,
}

impl DirectoryCursor {
    fn from_entry(
        entry: &Entry,
        column: FileSortColumn,
        direction: FileSortDirection,
    ) -> io::Result<Self> {
        let modified_nanos = entry
            .modified
            .map(|modified| {
                modified
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| invalid_cursor())?
                    .as_nanos()
                    .try_into()
                    .map_err(|_| invalid_cursor())
            })
            .transpose()?;
        Ok(Self {
            version: 1,
            column,
            direction,
            name: entry.name.clone(),
            is_dir: entry.is_dir,
            len: entry.len,
            modified_nanos,
        })
    }

    fn entry(&self) -> Entry {
        Entry {
            name: self.name.clone(),
            is_dir: self.is_dir,
            len: self.len,
            modified: self
                .modified_nanos
                .map(|nanos| UNIX_EPOCH + std::time::Duration::from_nanos(nanos)),
        }
    }
}

fn invalid_cursor() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "Invalid directory cursor")
}

fn encode_directory_cursor(
    entry: &Entry,
    column: FileSortColumn,
    direction: FileSortDirection,
) -> io::Result<String> {
    let json = serde_json::to_vec(&DirectoryCursor::from_entry(entry, column, direction)?)
        .map_err(|_| invalid_cursor())?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

fn decode_directory_cursor(
    value: &str,
    column: FileSortColumn,
    direction: FileSortDirection,
) -> io::Result<Entry> {
    if value.is_empty() || value.len() > DIRECTORY_CURSOR_MAX_BYTES {
        return Err(invalid_cursor());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid_cursor())?;
    if bytes.len() > DIRECTORY_CURSOR_MAX_BYTES {
        return Err(invalid_cursor());
    }
    let cursor: DirectoryCursor = serde_json::from_slice(&bytes).map_err(|_| invalid_cursor())?;
    if cursor.version != 1 || cursor.column != column || cursor.direction != direction {
        return Err(invalid_cursor());
    }
    Ok(cursor.entry())
}

#[derive(Debug)]
struct RankedEntry {
    entry: Entry,
    key: DirectoryEntrySortKey,
    direction: FileSortDirection,
    reverse: bool,
}

impl PartialEq for RankedEntry {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for RankedEntry {}

impl PartialOrd for RankedEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RankedEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        let order = directed_key_order(&self.key, &other.key, self.direction);
        if self.reverse {
            order.reverse()
        } else {
            order
        }
    }
}

fn retain_ranked_entry(
    heap: &mut BinaryHeap<RankedEntry>,
    entry: Entry,
    key: DirectoryEntrySortKey,
    direction: FileSortDirection,
    backwards: bool,
) {
    heap.push(RankedEntry {
        entry,
        key,
        direction,
        reverse: backwards,
    });
    if heap.len() > DIRECTORY_PAGE_SIZE + 1 {
        heap.pop();
    }
}

#[derive(Debug, Default)]
pub(super) struct DirectoryCursorPage {
    pub(super) entries: Vec<Entry>,
    pub(super) previous_cursor: Option<String>,
    pub(super) next_cursor: Option<String>,
    #[cfg(test)]
    pub(super) scanned: usize,
    pub(super) truncated: bool,
    #[cfg(test)]
    pub(super) peak_retained: usize,
}

pub(super) fn list_directory_cursor_page<D: DirectoryAccess>(
    directory: &D,
    relative: &str,
    after: Option<&str>,
    before: Option<&str>,
    scan_limit: usize,
    column: FileSortColumn,
    direction: FileSortDirection,
) -> io::Result<DirectoryCursorPage> {
    if after.is_some() && before.is_some() {
        return Err(invalid_cursor());
    }
    let started = Instant::now();
    let boundary = after
        .or(before)
        .map(|cursor| decode_directory_cursor(cursor, column, direction))
        .transpose()?;
    let boundary_key = boundary.as_ref().map(|entry| entry_sort_key(entry, column));
    let backwards = before.is_some();
    let mut heap = BinaryHeap::with_capacity(DIRECTORY_PAGE_SIZE + 1);
    let mut scanned = 0usize;
    let mut truncated = false;
    let mut scan = directory.scan_entries(relative)?;
    loop {
        let remaining = scan_limit.saturating_sub(scanned);
        if remaining == 0 {
            let sentinel = scan.run_batch(1)?;
            truncated = sentinel.scanned != 0 || !sentinel.complete;
            break;
        }
        let batch = scan.run_batch(remaining.min(256))?;
        scanned = scanned.saturating_add(batch.scanned);
        for entry in batch.entries {
            let key = entry_sort_key(&entry, column);
            let include = boundary_key.as_ref().is_none_or(|boundary| {
                let order = directed_key_order(&key, boundary, direction);
                if backwards {
                    order.is_lt()
                } else {
                    order.is_gt()
                }
            });
            if !include {
                continue;
            }
            retain_ranked_entry(&mut heap, entry, key, direction, backwards);
        }
        if batch.complete {
            break;
        }
    }
    #[cfg(test)]
    let peak_retained = heap.len();
    let mut ranked = heap.into_vec();
    ranked.sort_by(|left, right| directed_key_order(&left.key, &right.key, direction));
    let mut entries = ranked
        .into_iter()
        .map(|ranked| ranked.entry)
        .collect::<Vec<_>>();
    let has_more = entries.len() > DIRECTORY_PAGE_SIZE;
    if has_more {
        if backwards {
            entries.remove(0);
        } else {
            entries.pop();
        }
    }
    let previous_cursor = if !entries.is_empty() && (has_more && backwards || after.is_some()) {
        Some(encode_directory_cursor(&entries[0], column, direction)?)
    } else {
        None
    };
    let next_cursor = if !entries.is_empty() && (has_more && !backwards || before.is_some()) {
        Some(encode_directory_cursor(
            entries.last().expect("non-empty page"),
            column,
            direction,
        )?)
    } else {
        None
    };
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    tracing::info!(
        directory = %EscapedLogPath::new(relative),
        scanned,
        returned = entries.len(),
        truncated,
        elapsed_ms,
        "directory listing scan completed"
    );
    Ok(DirectoryCursorPage {
        entries,
        previous_cursor,
        next_cursor,
        #[cfg(test)]
        scanned,
        truncated,
        #[cfg(test)]
        peak_retained,
    })
}

/// Captures and sorts one point-in-time directory view for short-lived cursor
/// pagination. Returning `None` means that the 8 MiB snapshot ceiling was hit;
/// callers must use `list_directory_cursor_page`'s bounded 101-entry heap.
pub(super) fn build_directory_snapshot<D: DirectoryAccess>(
    directory: &D,
    relative: &str,
    scan_limit: usize,
    column: FileSortColumn,
    direction: FileSortDirection,
) -> io::Result<Option<DirectorySnapshot>> {
    let started = Instant::now();
    let mut builder = DirectorySnapshotBuilder::new();
    let mut scanned = 0usize;
    let mut truncated = false;
    let mut scan = directory.scan_entries(relative)?;
    loop {
        let remaining = scan_limit.saturating_sub(scanned);
        if remaining == 0 {
            let sentinel = scan.run_batch(1)?;
            truncated = sentinel.scanned != 0 || !sentinel.complete;
            break;
        }
        let batch = scan.run_batch(remaining.min(256))?;
        scanned = scanned.saturating_add(batch.scanned);
        for entry in batch.entries {
            let sort_key = entry_sort_key(&entry, column);
            if builder.push(entry, sort_key).is_err() {
                tracing::info!(
                    directory = %EscapedLogPath::new(relative),
                    scanned,
                    cacheable = false,
                    "directory snapshot exceeded its memory ceiling"
                );
                return Ok(None);
            }
        }
        if batch.complete {
            break;
        }
    }
    let mut snapshot = builder.finish(truncated);
    snapshot
        .entries
        .sort_by(|left, right| directed_key_order(&left.sort_key, &right.sort_key, direction));
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    tracing::info!(
        directory = %EscapedLogPath::new(relative),
        scanned,
        retained = snapshot.entries.len(),
        truncated,
        elapsed_ms,
        cacheable = true,
        "directory snapshot scan completed"
    );
    Ok(Some(snapshot))
}

fn clone_entry(entry: &Entry) -> Entry {
    Entry {
        name: entry.name.clone(),
        is_dir: entry.is_dir,
        len: entry.len,
        modified: entry.modified,
    }
}

/// Pages a snapshot that is already sorted for `column` and `direction`.
pub(super) fn list_directory_snapshot_cursor_page(
    snapshot: &DirectorySnapshot,
    after: Option<&str>,
    before: Option<&str>,
    column: FileSortColumn,
    direction: FileSortDirection,
) -> io::Result<DirectoryCursorPage> {
    if after.is_some() && before.is_some() {
        return Err(invalid_cursor());
    }
    let boundary = after
        .or(before)
        .map(|cursor| decode_directory_cursor(cursor, column, direction))
        .transpose()?;
    let boundary_key = boundary.as_ref().map(|entry| entry_sort_key(entry, column));
    let entries = snapshot.entries.as_ref();
    let (start, end, backwards) = if before.is_some() {
        let end = boundary_key.as_ref().map_or(entries.len(), |boundary| {
            entries.partition_point(|entry| {
                entry
                    .compare_key(boundary, direction == FileSortDirection::Descending)
                    .is_lt()
            })
        });
        (end.saturating_sub(DIRECTORY_PAGE_SIZE + 1), end, true)
    } else {
        let start = boundary_key.as_ref().map_or(0usize, |boundary| {
            entries.partition_point(|entry| {
                !entry
                    .compare_key(boundary, direction == FileSortDirection::Descending)
                    .is_gt()
            })
        });
        (
            start,
            start
                .saturating_add(DIRECTORY_PAGE_SIZE + 1)
                .min(entries.len()),
            false,
        )
    };
    let mut page_entries = entries[start..end]
        .iter()
        .map(|entry| clone_entry(&entry.entry))
        .collect::<Vec<_>>();
    let has_more = page_entries.len() > DIRECTORY_PAGE_SIZE;
    if has_more {
        if backwards {
            page_entries.remove(0);
        } else {
            page_entries.pop();
        }
    }
    let previous_cursor = if !page_entries.is_empty() && (has_more && backwards || after.is_some())
    {
        Some(encode_directory_cursor(
            &page_entries[0],
            column,
            direction,
        )?)
    } else {
        None
    };
    let next_cursor = if !page_entries.is_empty() && (has_more && !backwards || before.is_some()) {
        Some(encode_directory_cursor(
            page_entries.last().expect("non-empty page"),
            column,
            direction,
        )?)
    } else {
        None
    };
    Ok(DirectoryCursorPage {
        entries: page_entries,
        previous_cursor,
        next_cursor,
        #[cfg(test)]
        scanned: 0,
        truncated: snapshot.truncated,
        #[cfg(test)]
        peak_retained: 0,
    })
}

pub(super) fn search_tree<D: DirectoryAccess>(
    secure_root: &D,
    base: &str,
    query: &str,
    settings: &RuntimeSettings,
) -> std::io::Result<Vec<SearchHit>> {
    let needle = query.to_ascii_lowercase();
    let mut scanned_entries = 0usize;
    let mut results = Vec::new();
    let mut queue = VecDeque::from([base.to_string()]);
    while let Some(directory) = queue.pop_front() {
        let mut scan = secure_root.scan_entries(&directory)?;
        loop {
            let remaining = settings.max_search_entries.saturating_sub(scanned_entries);
            if remaining == 0 {
                return Ok(results);
            }
            let batch = scan.run_batch(remaining.min(100))?;
            scanned_entries = scanned_entries.saturating_add(batch.scanned);
            for entry in batch.entries {
                let relative_path = join_display(&directory, &entry.name);
                if entry.name.to_ascii_lowercase().contains(&needle)
                    && results.len() < settings.max_search_results
                {
                    results.push(SearchHit {
                        relative_path: relative_path.clone(),
                        entry: Entry {
                            name: entry.name.clone(),
                            is_dir: entry.is_dir,
                            len: entry.len,
                            modified: entry.modified,
                        },
                    });
                }
                if entry.is_dir {
                    queue.push_back(relative_path);
                }
                if results.len() >= settings.max_search_results {
                    return Ok(results);
                }
            }
            if batch.complete {
                break;
            }
        }
    }
    Ok(results)
}

include!("common/directory_cursor_tests.rs");
