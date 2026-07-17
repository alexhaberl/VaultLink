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
    rendering::{esc, GB, MB},
    AppError, Result,
};
use crate::{
    i18n::{self, Locale},
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

#[cfg(test)]
mod webauthn_response_tests {
    use super::*;

    #[test]
    fn capacity_exhaustion_returns_retryable_service_unavailable() {
        let response = webauthn_start_response::<serde_json::Value>(Err(
            WebAuthnServiceError::CapacityExceeded,
        ))
        .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("60"))
        );
    }

    #[test]
    fn ceremony_errors_keep_the_existing_bad_request_contract() {
        let error = webauthn_start_response::<serde_json::Value>(Err(
            WebAuthnServiceError::Ceremony("invalid challenge".into()),
        ))
        .unwrap_err();

        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(!error.1.is_empty());
    }
}

pub(super) fn format_audit_time(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| {
            let utc = dt.with_timezone(&Utc);
            match i18n::current_locale() {
                Locale::De => utc.format("%d.%m.%Y %H:%M:%S").to_string(),
                Locale::En => utc.format("%Y-%m-%d %H:%M:%S").to_string(),
            }
        })
        .unwrap_or_else(|_| value.to_string())
}

pub(super) fn format_file_time(value: std::time::SystemTime) -> String {
    let utc = DateTime::<Utc>::from(value);
    format!(
        r#"<time data-local-time datetime="{}">{}</time>"#,
        utc.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        format_utc_minute(utc),
    )
}

pub(super) fn format_utc_minute(value: DateTime<Utc>) -> String {
    match i18n::current_locale() {
        Locale::De => value.format("%d.%m.%Y %H:%M UTC").to_string(),
        Locale::En => value.format("%Y-%m-%d %H:%M UTC").to_string(),
    }
}

pub(super) fn format_public_date(value: DateTime<Utc>) -> String {
    match i18n::current_locale() {
        Locale::De => value.format("%d.%m.%Y").to_string(),
        Locale::En => value.format("%Y-%m-%d").to_string(),
    }
}

pub(super) fn internal<T>(_: T) -> AppError {
    AppError(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
}
pub(super) fn decode_security_keys(
    rows: &[crate::db::AdminWebauthnCredential],
) -> Result<Vec<crate::webauthn::StoredCredential>> {
    rows.iter()
        .map(|row| {
            crate::webauthn::StoredCredential::from_blob(&row.credential_blob).map_err(internal)
        })
        .collect()
}

#[derive(Deserialize)]
pub(super) struct CsrfForm {
    pub(super) csrf: String,
}
#[derive(Default, Deserialize)]
pub(crate) struct BrowseQuery {
    pub(super) path: Option<String>,
    pub(super) after: Option<String>,
    pub(super) before: Option<String>,
    pub(super) q: Option<String>,
    pub(super) sort: Option<String>,
    pub(super) direction: Option<String>,
    pub(super) upload: Option<String>,
    pub(super) notice: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum FileSortColumn {
    Name,
    Type,
    Size,
    Modified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum FileSortDirection {
    Ascending,
    Descending,
}

pub(super) fn file_sort_column(value: Option<&str>) -> FileSortColumn {
    match value {
        Some("type") => FileSortColumn::Type,
        Some("size") => FileSortColumn::Size,
        Some("modified") => FileSortColumn::Modified,
        _ => FileSortColumn::Name,
    }
}

pub(super) fn file_sort_column_value(column: FileSortColumn) -> &'static str {
    match column {
        FileSortColumn::Name => "name",
        FileSortColumn::Type => "type",
        FileSortColumn::Size => "size",
        FileSortColumn::Modified => "modified",
    }
}

pub(super) fn file_sort_direction(value: Option<&str>) -> FileSortDirection {
    match value {
        Some("desc") => FileSortDirection::Descending,
        _ => FileSortDirection::Ascending,
    }
}

pub(super) fn file_sort_direction_value(direction: FileSortDirection) -> &'static str {
    match direction {
        FileSortDirection::Ascending => "asc",
        FileSortDirection::Descending => "desc",
    }
}

fn compare_entries(left: &Entry, right: &Entry, column: FileSortColumn) -> Ordering {
    let by_name = || {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.name.cmp(&right.name))
    };
    match column {
        FileSortColumn::Name => by_name(),
        FileSortColumn::Type => (!left.is_dir).cmp(&(!right.is_dir)).then_with(by_name),
        FileSortColumn::Size => left.len.cmp(&right.len).then_with(by_name),
        FileSortColumn::Modified => left.modified.cmp(&right.modified).then_with(by_name),
    }
}

fn compare_entries_directed(
    left: &Entry,
    right: &Entry,
    column: FileSortColumn,
    direction: FileSortDirection,
) -> Ordering {
    let order = compare_entries(left, right, column);
    if direction == FileSortDirection::Descending {
        order.reverse()
    } else {
        order
    }
}

pub(super) fn sort_entries(
    entries: &mut [Entry],
    column: FileSortColumn,
    direction: FileSortDirection,
) {
    entries.sort_by(|left, right| {
        let order = compare_entries(left, right, column);
        if direction == FileSortDirection::Descending {
            order.reverse()
        } else {
            order
        }
    });
}

pub(super) fn sort_search_hits(
    hits: &mut [SearchHit],
    column: FileSortColumn,
    direction: FileSortDirection,
) {
    hits.sort_by(|left, right| {
        let order = compare_entries(&left.entry, &right.entry, column);
        if direction == FileSortDirection::Descending {
            order.reverse()
        } else {
            order
        }
    });
}

pub(super) fn file_sort_header(
    label: &str,
    column: FileSortColumn,
    current_column: FileSortColumn,
    current_direction: FileSortDirection,
    base_url: &str,
    path: &str,
    search: Option<&str>,
) -> String {
    let active = column == current_column;
    let next_direction = if active && current_direction == FileSortDirection::Ascending {
        FileSortDirection::Descending
    } else {
        FileSortDirection::Ascending
    };
    let aria_sort = if active {
        match current_direction {
            FileSortDirection::Ascending => "ascending",
            FileSortDirection::Descending => "descending",
        }
    } else {
        "none"
    };
    let indicator = if active {
        match current_direction {
            FileSortDirection::Ascending => "↑",
            FileSortDirection::Descending => "↓",
        }
    } else {
        ""
    };
    let search = search
        .map(|value| format!("&q={}", encoded(value)))
        .unwrap_or_default();
    let href = format!(
        "{base_url}?path={}&sort={}&direction={}{}",
        encoded(path),
        file_sort_column_value(column),
        file_sort_direction_value(next_direction),
        search,
    );
    format!(
        r#"<th aria-sort="{aria_sort}"><a class="vl-audit-sort" href="{}">{label}<span class="vl-audit-sort__indicator" aria-hidden="true">{indicator}</span></a></th>"#,
        esc(&href)
    )
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
    super::templates::TrustedMarkup::generated_qr(data).map_err(internal)
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

pub(super) fn breadcrumbs(path: &str, base_url: &str) -> String {
    let clean = path.trim_matches('/');
    let mut html = String::from(
        r#"<p class="vl-inline-actions"><a class="vl-button vl-button--secondary" href=""#,
    );
    html.push_str(base_url);
    html.push_str(r#"">/</a>"#);
    if clean.is_empty() {
        html.push_str("</p>");
        return html;
    }
    let mut current = String::new();
    for part in clean.split('/') {
        current = join_display(&current, part);
        html.push_str(" / ");
        html.push_str(&format!(
            r#"<a class="vl-button vl-button--secondary" href="{}?path={}">{}</a>"#,
            base_url,
            encoded(&current),
            esc(part)
        ));
    }
    html.push_str("</p>");
    html
}

pub(super) fn public_breadcrumbs(token: &str, path: &str) -> String {
    breadcrumbs(path, &format!("/v/{token}"))
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
    column: FileSortColumn,
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
        let order =
            compare_entries_directed(&self.entry, &other.entry, self.column, self.direction);
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
    column: FileSortColumn,
    direction: FileSortDirection,
    backwards: bool,
) {
    heap.push(RankedEntry {
        entry,
        column,
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
            let include = boundary.as_ref().is_none_or(|boundary| {
                let order = compare_entries_directed(&entry, boundary, column, direction);
                if backwards {
                    order.is_lt()
                } else {
                    order.is_gt()
                }
            });
            if !include {
                continue;
            }
            retain_ranked_entry(&mut heap, entry, column, direction, backwards);
        }
        if batch.complete {
            break;
        }
    }
    #[cfg(test)]
    let peak_retained = heap.len();
    let mut entries = heap
        .into_iter()
        .map(|ranked| ranked.entry)
        .collect::<Vec<_>>();
    sort_entries(&mut entries, column, direction);
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
        directory = relative,
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

#[cfg(test)]
mod directory_cursor_tests {
    use super::*;

    fn entry(index: usize) -> Entry {
        Entry {
            name: format!("entry-{index:05}.txt"),
            is_dir: index.is_multiple_of(7),
            len: (50_000 - index) as u64,
            modified: Some(UNIX_EPOCH + std::time::Duration::from_secs((index % 997) as u64)),
        }
    }

    fn identity(entry: &Entry) -> (&str, bool, u64, Option<std::time::SystemTime>) {
        (&entry.name, entry.is_dir, entry.len, entry.modified)
    }

    #[test]
    fn fifty_thousand_entry_reference_sort_retains_at_most_101_candidates() {
        for column in [
            FileSortColumn::Name,
            FileSortColumn::Type,
            FileSortColumn::Size,
            FileSortColumn::Modified,
        ] {
            for direction in [FileSortDirection::Ascending, FileSortDirection::Descending] {
                let mut expected = (0..50_000).map(entry).collect::<Vec<_>>();
                sort_entries(&mut expected, column, direction);
                for backwards in [false, true] {
                    let mut heap = BinaryHeap::new();
                    for candidate in (0..50_000).map(entry) {
                        retain_ranked_entry(&mut heap, candidate, column, direction, backwards);
                        assert!(heap.len() <= 101);
                    }
                    let mut actual = heap
                        .into_iter()
                        .map(|ranked| ranked.entry)
                        .collect::<Vec<_>>();
                    sort_entries(&mut actual, column, direction);
                    let reference = if backwards {
                        &expected[expected.len() - 101..]
                    } else {
                        &expected[..101]
                    };
                    assert_eq!(
                        actual.iter().map(identity).collect::<Vec<_>>(),
                        reference.iter().map(identity).collect::<Vec<_>>()
                    );
                }
            }
        }
    }

    #[test]
    fn directory_cursor_is_versioned_bounded_and_bound_to_sorting() {
        let boundary = entry(42);
        let cursor = encode_directory_cursor(
            &boundary,
            FileSortColumn::Modified,
            FileSortDirection::Descending,
        )
        .unwrap();
        assert!(cursor.len() <= DIRECTORY_CURSOR_MAX_BYTES);
        let decoded = decode_directory_cursor(
            &cursor,
            FileSortColumn::Modified,
            FileSortDirection::Descending,
        )
        .unwrap();
        assert_eq!(identity(&decoded), identity(&boundary));
        assert!(decode_directory_cursor(
            &cursor,
            FileSortColumn::Name,
            FileSortDirection::Descending
        )
        .is_err());
        assert!(decode_directory_cursor(
            &"x".repeat(DIRECTORY_CURSOR_MAX_BYTES + 1),
            FileSortColumn::Name,
            FileSortDirection::Ascending
        )
        .is_err());
    }
}
