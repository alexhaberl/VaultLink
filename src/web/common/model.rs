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

pub(super) fn decode_security_keys(
    rows: &[crate::db::AdminWebauthnCredential],
) -> Result<Vec<crate::webauthn::StoredCredential>> {
    rows.iter()
        .map(|row| {
            crate::webauthn::StoredCredential::from_blob(&row.credential_blob).map_err(|error| {
                AppError::from(report_internal(
                    InternalOperation::WebCommonCredentialDecode,
                    error,
                ))
            })
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
