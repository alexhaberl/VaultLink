use std::fmt::Write as _;

use serde::{Deserialize as _, Deserializer};
use time::{
    error::{Parse, ParseFromDescription, TryFromParsed},
    format_description::well_known::Rfc3339,
    macros::format_description,
    OffsetDateTime, UtcOffset,
};

pub(crate) trait TimestampExt {
    fn to_rfc3339(self) -> String;
    fn to_rfc3339_z(self) -> String;
    fn to_rfc3339_seconds(self) -> String;
}

impl TimestampExt for OffsetDateTime {
    fn to_rfc3339(self) -> String {
        format_utc(self, "+00:00", true)
    }

    fn to_rfc3339_z(self) -> String {
        format_utc(self, "Z", true)
    }

    fn to_rfc3339_seconds(self) -> String {
        format_utc(self, "Z", false)
    }
}

fn format_utc(value: OffsetDateTime, suffix: &str, fractional: bool) -> String {
    let utc = value.to_offset(UtcOffset::UTC);
    let mut output = utc
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]"
        ))
        .expect("UTC timestamp always has date and time components");
    let nanos = utc.nanosecond();
    // Keep the existing SQLite and JSON precision groups. In particular,
    // SQLite compares stored timestamps and query parameters as text.
    if fractional && nanos != 0 {
        if nanos.is_multiple_of(1_000_000) {
            write!(output, ".{:03}", nanos / 1_000_000).unwrap();
        } else if nanos.is_multiple_of(1_000) {
            write!(output, ".{:06}", nanos / 1_000).unwrap();
        } else {
            write!(output, ".{nanos:09}").unwrap();
        }
    }
    output.push_str(suffix);
    output
}

pub(crate) fn parse_rfc3339(value: &str) -> Result<OffsetDateTime, Parse> {
    let parsed = if value.starts_with(['+', '-']) {
        // Previous JSON inputs also supported ISO 8601 signed years.
        let expanded;
        let value = if let Some(prefix) = value.strip_suffix(['Z', 'z']) {
            expanded = format!("{prefix}+00:00");
            &expanded
        } else {
            value
        };
        OffsetDateTime::parse(
            value,
            format_description!(
                version = 2,
                "[year]-[month]-[day][first [T][t][ ]][hour]:[minute]:[second][optional [.[subsecond]]][offset_hour sign:mandatory]:[offset_minute]"
            ),
        )?
    } else {
        // time's RFC3339 parser permits any byte between the date and time.
        if !matches!(value.as_bytes().get(10), Some(b'T' | b't' | b' ')) {
            return Err(ParseFromDescription::InvalidComponent("date-time separator").into());
        }
        OffsetDateTime::parse(value, &Rfc3339)?
    };
    OffsetDateTime::from_unix_timestamp_nanos(parsed.unix_timestamp_nanos())
        .map_err(|error| TryFromParsed::from(error).into())
}

pub(crate) fn deserialize_optional<'de, D>(
    deserializer: D,
) -> Result<Option<OffsetDateTime>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .map_err(serde::de::Error::custom)
}

pub(crate) fn month_key(value: OffsetDateTime) -> String {
    value
        .to_offset(UtcOffset::UTC)
        .format(format_description!("[year]-[month]"))
        .expect("UTC timestamp always has year and month components")
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn storage_and_api_timestamps_preserve_utc_suffix_and_precision() {
        for (date, body) in [
            (datetime!(2026-11-17 09:00:00 +01:00), "2026-11-17T08:00:00"),
            (
                datetime!(2026-11-17 08:00:00.1 UTC),
                "2026-11-17T08:00:00.100",
            ),
            (
                datetime!(2026-11-17 08:00:00.0001 UTC),
                "2026-11-17T08:00:00.000100",
            ),
            (
                datetime!(2026-11-17 08:00:00.000000001 UTC),
                "2026-11-17T08:00:00.000000001",
            ),
        ] {
            assert_eq!(date.to_rfc3339(), format!("{body}+00:00"));
            assert_eq!(date.to_rfc3339_z(), format!("{body}Z"));
            assert_eq!(parse_rfc3339(&date.to_rfc3339()).unwrap(), date);
            assert_eq!(date.to_rfc3339_seconds(), "2026-11-17T08:00:00Z");
        }
    }

    #[test]
    fn parses_legacy_utc_text_and_normalizes_offsets() {
        for value in [
            "2026-11-17 08:00:00+00:00",
            "2026-11-17t08:00:00z",
            "2026-11-17T09:00:00+01:00",
        ] {
            let parsed = parse_rfc3339(value).unwrap();
            assert_eq!(parsed, datetime!(2026-11-17 08:00 UTC));
            assert_eq!(parsed.offset(), UtcOffset::UTC);
        }
        let expanded = parse_rfc3339("+10000-01-01T00:00:00Z").unwrap();
        assert_eq!(expanded.to_rfc3339_z(), "+10000-01-01T00:00:00Z");
        assert!(parse_rfc3339("2026-11-17_08:00:00Z").is_err());
    }
}
