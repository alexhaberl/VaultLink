use super::{
    insert_required_audits, token_hash, trace_required_audits, AuditAction, AuditContext, Audited,
    Database, Permission, RequiredAuditEvent, TransferAvailabilityOutcome,
    TransferLeaseBeginOutcome, TransferLeaseCancelOutcome, TransferLeaseCompleteOutcome,
    TransferLeaseHeartbeatOutcome, TransferMonthlyCounts, UploadReservationBeginOutcome,
    UploadReservationCommitOutcome, UploadReservationExtendOutcome, MAX_SQLITE_UNSIGNED,
    TRANSFER_LEASE_MAX_LIFETIME_SECONDS, TRANSFER_SESSION_TTL_SECONDS,
};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

const UPLOAD_RESERVATION_TTL_SECONDS: i64 = 15 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransferAccessState {
    Available,
    ExistingGrant { grant_id: i64, counted: bool },
    LimitReached,
    ShareUnavailable,
}

fn transfer_deadlines() -> (String, String) {
    let now = Utc::now();
    let expires = now + Duration::seconds(TRANSFER_SESSION_TTL_SECONDS);
    (now.to_rfc3339(), expires.to_rfc3339())
}

pub(super) fn current_utc_month() -> String {
    Utc::now().format("%Y-%m").to_string()
}

fn valid_utc_month(month: &str) -> bool {
    let bytes = month.as_bytes();
    if !(bytes.len() == 7
        && bytes[4] == b'-'
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..].iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    let numeric_month = (bytes[5] - b'0') * 10 + (bytes[6] - b'0');
    (1..=12).contains(&numeric_month)
}

fn increment_transfer_monthly_count(
    transaction: &Transaction<'_>,
    month: &str,
    action: &str,
) -> rusqlite::Result<()> {
    if !matches!(action, "download" | "zip_download" | "preview") {
        return Ok(());
    }
    transaction.execute(
        "INSERT INTO transfer_monthly_counts(month,action,count) VALUES(?1,?2,1)
         ON CONFLICT(month,action) DO UPDATE SET count=count+1",
        params![month, action],
    )?;
    Ok(())
}

fn required_transfer_audit_action(action: &str) -> rusqlite::Result<AuditAction> {
    match action {
        "download" => Ok(AuditAction::Download),
        "zip_download" => Ok(AuditAction::ZipDownload),
        "preview" => Ok(AuditAction::Preview),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn cleanup_transfer_state(transaction: &Transaction<'_>, now: &str) -> rusqlite::Result<()> {
    transaction.execute(
        "DELETE FROM public_transfer_leases WHERE expires_at<=?1",
        [now],
    )?;
    transaction.execute(
        "DELETE FROM public_transfer_grants
         WHERE expires_at<=?1
            OR (counted=0 AND NOT EXISTS(
                SELECT 1 FROM public_transfer_leases leases
                WHERE leases.grant_id=public_transfer_grants.id AND leases.expires_at>?1
            ))",
        [now],
    )?;
    Ok(())
}

fn cleanup_transfer_state_before_heartbeat(
    transaction: &Transaction<'_>,
    now: &str,
    current_lease_hash: &str,
) -> rusqlite::Result<()> {
    transaction.execute(
        "DELETE FROM public_transfer_leases
         WHERE expires_at<=?1 AND token_hash<>?2",
        params![now, current_lease_hash],
    )?;
    transaction.execute(
        "DELETE FROM public_transfer_grants
         WHERE id NOT IN(
                 SELECT grant_id FROM public_transfer_leases WHERE token_hash=?2
               )
           AND (expires_at<=?1
                OR (counted=0 AND NOT EXISTS(
                    SELECT 1 FROM public_transfer_leases leases
                    WHERE leases.grant_id=public_transfer_grants.id AND leases.expires_at>?1
                )))",
        params![now, current_lease_hash],
    )?;
    Ok(())
}

fn available_upload_share_total_limit(
    transaction: &Transaction<'_>,
    share_id: i64,
    upload_policy_epoch: i64,
    now: &str,
) -> rusqlite::Result<Option<u64>> {
    Ok(transaction
        .query_row(
            "SELECT max_upload_total_size
             FROM shares
             WHERE id=?1
               AND upload_policy_epoch=?3
               AND active=1
               AND (expires_at IS NULL OR expires_at>?2)
               AND is_directory=1
               AND permission IN ('upload_only','download_upload')
               AND max_upload_files IS NOT NULL",
            params![share_id, now, upload_policy_epoch],
            |row| row.get::<_, Option<u64>>(0),
        )
        .optional()?
        .flatten())
}

fn transfer_access_state(
    connection: &Connection,
    session_token_hash: &str,
    share_id: i64,
    resource_key: &str,
    action: &str,
    now: &str,
) -> rusqlite::Result<TransferAccessState> {
    let share = connection
        .query_row(
            "SELECT max_downloads,download_count FROM shares
             WHERE id=?1 AND active=1 AND (expires_at IS NULL OR expires_at>?2)
               AND permission IN ('download_only','download_upload')",
            params![share_id, now],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((max_downloads, download_count)) = share else {
        return Ok(TransferAccessState::ShareUnavailable);
    };

    let existing_grant = connection
        .query_row(
            "SELECT id,counted FROM public_transfer_grants
             WHERE session_token_hash=?1 AND share_id=?2
               AND resource_key=?3 AND action=?4 AND expires_at>?5",
            params![session_token_hash, share_id, resource_key, action, now],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)? != 0)),
        )
        .optional()?;
    if let Some((grant_id, counted)) = existing_grant {
        return Ok(TransferAccessState::ExistingGrant { grant_id, counted });
    }

    let pending_grants: i64 = connection.query_row(
        "SELECT COUNT(*) FROM public_transfer_grants grants
         WHERE grants.share_id=?1 AND grants.counted=0 AND grants.expires_at>?2
           AND EXISTS(
               SELECT 1 FROM public_transfer_leases leases
               WHERE leases.grant_id=grants.id AND leases.expires_at>?2
           )",
        params![share_id, now],
        |row| row.get(0),
    )?;
    if max_downloads.is_some_and(|maximum| download_count.saturating_add(pending_grants) >= maximum)
    {
        Ok(TransferAccessState::LimitReached)
    } else {
        Ok(TransferAccessState::Available)
    }
}

include!("transfers/reservations.rs");
include!("transfers/leases.rs");
include!("transfers/statistics.rs");
