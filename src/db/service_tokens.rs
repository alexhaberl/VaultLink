use super::{
    insert_required_audits, token_hash, trace_required_audits, valid_service_token_name,
    AuditAction, AuditContext, Audited, Database, MfaSessionProof, MonitoringShare,
    MonitoringShareListOptions, MonitoringShareListStatus, MonitoringSharePage,
    MonitoringShareStatus, MonitoringSummary, Permission, RequiredAuditEvent, ServiceToken,
    ServiceTokenAuthorizationOutcome, ServiceTokenCreationOutcome, SessionBound,
    TransferMonthlyCounts, MAX_SERVICE_TOKENS,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

pub(crate) const SERVICE_TOKEN_PREFIX: &str = "vlk_st_v1_";
pub(crate) const SERVICE_TOKEN_RANDOM_BYTES: usize = 32;
const SERVICE_TOKEN_TOUCH_INTERVAL_SECONDS: i64 = 5 * 60;

fn valid_service_token(token: &str) -> bool {
    let Some(encoded) = token.strip_prefix(SERVICE_TOKEN_PREFIX) else {
        return false;
    };
    URL_SAFE_NO_PAD
        .decode(encoded)
        .is_ok_and(|decoded| decoded.len() == SERVICE_TOKEN_RANDOM_BYTES)
}

fn map_service_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<ServiceToken> {
    Ok(ServiceToken {
        id: row.get(0)?,
        name: row.get(1)?,
        scope_mask: row.get(2)?,
        created_by: row.get(3)?,
        created_by_username: row.get(4)?,
        created_at: row.get(5)?,
        expires_at: row.get(6)?,
        last_used_at: row.get(7)?,
    })
}

fn parse_optional_timestamp(
    value: Option<String>,
    column: usize,
) -> rusqlite::Result<Option<DateTime<Utc>>> {
    value
        .map(|timestamp| {
            DateTime::parse_from_rfc3339(&timestamp)
                .map(|parsed| parsed.with_timezone(&Utc))
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        column,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
        })
        .transpose()
}

fn parse_monitoring_status(value: &str) -> rusqlite::Result<MonitoringShareStatus> {
    match value {
        "available" => Ok(MonitoringShareStatus::Available),
        "inactive" => Ok(MonitoringShareStatus::Inactive),
        "expired" => Ok(MonitoringShareStatus::Expired),
        "download_limit_reached" => Ok(MonitoringShareStatus::DownloadLimitReached),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

include!("service_tokens/management.rs");
include!("service_tokens/authorization.rs");
include!("service_tokens/monitoring.rs");

#[cfg(test)]
#[path = "service_tokens/tests.rs"]
mod tests;
