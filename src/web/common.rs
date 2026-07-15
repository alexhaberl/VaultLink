use std::{collections::VecDeque, io};

use axum::http::StatusCode;
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use qrcode::{render::svg, QrCode};
use serde::Deserialize;

use super::{esc, AppError, Result, GB, MB};
use crate::{
    i18n::{self, Locale},
    policy::{self, PreviewKind},
    runtime,
    runtime::RuntimeSettings,
    secure_fs::{DirectoryScan, Entry, SecureDirectory, SecureFile, SecureRoot},
    sensitive::SecretString,
};

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
    format_utc_minute(DateTime::<Utc>::from(value))
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
    AppError(StatusCode::INTERNAL_SERVER_ERROR, "Interner Fehler")
}
pub(super) fn decode_security_keys(
    rows: &[crate::db::AdminWebauthnCredential],
) -> Result<Vec<webauthn_rs::prelude::SecurityKey>> {
    rows.iter()
        .map(|row| serde_json::from_str(&row.credential_json).map_err(internal))
        .collect()
}

#[derive(Deserialize)]
pub(super) struct CsrfForm {
    pub(super) csrf: String,
}
#[derive(Default, Deserialize)]
pub(crate) struct BrowseQuery {
    pub(super) path: Option<String>,
    pub(super) page: Option<usize>,
    pub(super) q: Option<String>,
    pub(super) upload: Option<String>,
    pub(super) notice: Option<String>,
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

pub(super) fn expiry_picker_html() -> String {
    format!(
        r#"<label class="vl-field"><vl-i18n key="share.expires_optional"/><div class="vl-datetime-picker vl-input-action" data-datetime-picker><input name="expires_local" data-datetime-input placeholder="<vl-i18n key="date.placeholder"/>" autocomplete="off" inputmode="numeric"><button class="vl-button vl-button--secondary" type="button" data-datetime-toggle aria-label="<vl-i18n key="share.date_select"/>" aria-expanded="false">{}</button><div class="vl-datetime-popover" data-datetime-popover hidden><div class="vl-datetime-popover__grid"><label><vl-i18n key="date.year"/><select data-dt-year></select></label><label><vl-i18n key="date.month"/><select data-dt-month data-pad="2"></select></label><label><vl-i18n key="date.day"/><select data-dt-day data-pad="2"></select></label><label><vl-i18n key="date.hour"/><select data-dt-hour data-pad="2"></select></label><label><vl-i18n key="date.minute"/><select data-dt-minute data-pad="2"></select></label></div><div class="vl-datetime-popover__actions"><button class="vl-button vl-button--secondary vl-button--small" type="button" data-datetime-clear><vl-i18n key="common.delete"/></button><button class="vl-button vl-button--small" type="button" data-datetime-apply><vl-i18n key="common.apply"/></button></div></div></div><small><vl-i18n key="date.format"/></small></label>"#,
        crate::ui::icon(crate::ui::Icon::Calendar)
    )
}

pub(super) fn format_unit_floor(bytes: u64, unit: u64) -> String {
    (bytes / unit).to_string()
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
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiges Ablaufdatum"))?;
        let offset = offset_minutes
            .unwrap_or("0")
            .trim()
            .parse::<i64>()
            .map_err(|_| AppError(StatusCode::BAD_REQUEST, "Ungültiges Ablaufdatum"))?;
        if !(-1_440..=1_440).contains(&offset) {
            return Err(AppError(StatusCode::BAD_REQUEST, "Ungültiges Ablaufdatum"));
        }
        let utc_naive = naive
            .checked_add_signed(Duration::minutes(offset))
            .ok_or(AppError(StatusCode::BAD_REQUEST, "Ungültiges Ablaufdatum"))?;
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
    total
        .checked_add(chunk as u64)
        .filter(|new_total| *new_total <= maximum)
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

pub(super) fn qr_svg(data: &str) -> Result<String> {
    let code = QrCode::new(data.as_bytes()).map_err(internal)?;
    Ok(code
        .render::<svg::Color<'_>>()
        .min_dimensions(220, 220)
        .dark_color(svg::Color("#081226"))
        .light_color(svg::Color("#f8fbff"))
        .build())
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

pub(super) fn public_preview_error(error: io::Error) -> AppError {
    // Linux openat2 reports EXDEV/ELOOP when resolution would cross the
    // descriptor-bound share or follow a forbidden final symlink. Keep that
    // security boundary indistinguishable from a missing public file.
    if matches!(error.raw_os_error(), Some(18 | 40)) {
        return AppError(StatusCode::NOT_FOUND, "Datei nicht verfügbar");
    }
    match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => {
            AppError(StatusCode::NOT_FOUND, "Datei nicht verfügbar")
        }
        _ => AppError(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Vorschau nicht erlaubt"),
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

pub(super) fn search_tree<D: DirectoryAccess>(
    secure_root: D,
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
