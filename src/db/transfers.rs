use super::{
    insert_required_audits, token_hash, trace_required_audits, AuditAction, AuditContext, Database,
    Permission, RequiredAuditEvent, TransferAvailabilityOutcome, TransferLeaseBeginOutcome,
    TransferLeaseCancelOutcome, TransferLeaseCompleteOutcome, TransferLeaseHeartbeatOutcome,
    TransferMonthlyCounts, UploadReservationBeginOutcome, UploadReservationCommitOutcome,
    UploadReservationExtendOutcome, MAX_SQLITE_UNSIGNED, TRANSFER_LEASE_MAX_LIFETIME_SECONDS,
    TRANSFER_SESSION_TTL_SECONDS,
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

impl Database {
    pub fn begin_upload_reservation(
        &self,
        token: &str,
        share_id: i64,
        expected_upload_policy_epoch: i64,
    ) -> rusqlite::Result<UploadReservationBeginOutcome> {
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let expires = (now + Duration::seconds(UPLOAD_RESERVATION_TTL_SECONDS)).to_rfc3339();
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM public_upload_reservations WHERE expires_at<=?1",
            [&now_text],
        )?;
        let limits = transaction
            .query_row(
                "SELECT max_upload_total_size,max_upload_files,
                        active,(expires_at IS NULL OR expires_at>?2),
                        is_directory,permission
                 FROM shares WHERE id=?1 AND upload_policy_epoch=?3",
                params![share_id, now_text, expected_upload_policy_epoch],
                |row| {
                    Ok((
                        row.get::<_, Option<u64>>(0)?,
                        row.get::<_, Option<u64>>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, bool>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            Some(total_limit),
            Some(file_limit),
            active,
            unexpired,
            is_directory,
            permission,
        )) = limits
        else {
            transaction.commit()?;
            return Ok(UploadReservationBeginOutcome::ShareUnavailable);
        };
        if !active
            || !unexpired
            || !is_directory
            || !Permission::parse(&permission).is_some_and(|value| value.can_upload())
        {
            transaction.commit()?;
            return Ok(UploadReservationBeginOutcome::ShareUnavailable);
        }
        let (uploaded_bytes, uploaded_files): (u64, u64) = transaction.query_row(
            "SELECT COALESCE(uploaded_bytes,0),COALESCE(uploaded_files,0)
             FROM (SELECT 1) LEFT JOIN public_upload_usage ON share_id=?1",
            [share_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let active_reservations: u64 = transaction.query_row(
            "SELECT COUNT(*) FROM public_upload_reservations
             WHERE share_id=?1 AND upload_policy_epoch=?2",
            params![share_id, expected_upload_policy_epoch],
            |row| row.get(0),
        )?;
        if uploaded_bytes >= total_limit {
            transaction.commit()?;
            return Ok(UploadReservationBeginOutcome::ByteQuotaReached);
        }
        if uploaded_files.saturating_add(active_reservations) >= file_limit {
            transaction.commit()?;
            return Ok(UploadReservationBeginOutcome::FileQuotaReached);
        }
        transaction.execute(
            "INSERT INTO public_upload_reservations(
                 token_hash,share_id,reserved_bytes,created_at,expires_at,upload_policy_epoch
             ) VALUES(?1,?2,0,?3,?4,?5)",
            params![
                token_hash(token),
                share_id,
                now_text,
                expires,
                expected_upload_policy_epoch
            ],
        )?;
        transaction.commit()?;
        Ok(UploadReservationBeginOutcome::Reserved)
    }

    pub fn extend_upload_reservation(
        &self,
        token: &str,
        reserved_bytes: u64,
    ) -> rusqlite::Result<UploadReservationExtendOutcome> {
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let expires = (now + Duration::seconds(UPLOAD_RESERVATION_TTL_SECONDS)).to_rfc3339();
        let reservation_hash = token_hash(token);
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM public_upload_reservations WHERE expires_at<=?1",
            [&now_text],
        )?;
        let reservation = transaction
            .query_row(
                "SELECT share_id,reserved_bytes,upload_policy_epoch
                 FROM public_upload_reservations WHERE token_hash=?1",
                [&reservation_hash],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((share_id, current_bytes, upload_policy_epoch)) = reservation else {
            transaction.commit()?;
            return Ok(UploadReservationExtendOutcome::NotFound);
        };
        let Some(total_limit) = available_upload_share_total_limit(
            &transaction,
            share_id,
            upload_policy_epoch,
            &now_text,
        )?
        else {
            transaction.execute(
                "DELETE FROM public_upload_reservations WHERE token_hash=?1",
                [&reservation_hash],
            )?;
            transaction.commit()?;
            return Ok(UploadReservationExtendOutcome::ShareUnavailable);
        };
        if reserved_bytes < current_bytes {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if reserved_bytes > MAX_SQLITE_UNSIGNED {
            transaction.commit()?;
            return Ok(UploadReservationExtendOutcome::ByteQuotaReached);
        }
        let uploaded: u64 = transaction.query_row(
            "SELECT COALESCE((SELECT uploaded_bytes FROM public_upload_usage WHERE share_id=?1),0)",
            [share_id],
            |row| row.get(0),
        )?;
        let other_reserved: u64 = transaction.query_row(
            "SELECT COALESCE(SUM(reserved_bytes),0)
             FROM public_upload_reservations
             WHERE share_id=?1 AND token_hash<>?2 AND upload_policy_epoch=?3",
            params![share_id, reservation_hash, upload_policy_epoch],
            |row| row.get(0),
        )?;
        if uploaded
            .checked_add(other_reserved)
            .and_then(|value| value.checked_add(reserved_bytes))
            .is_none_or(|value| value > total_limit)
        {
            transaction.commit()?;
            return Ok(UploadReservationExtendOutcome::ByteQuotaReached);
        }
        transaction.execute(
            "UPDATE public_upload_reservations
             SET reserved_bytes=?2,expires_at=?3 WHERE token_hash=?1",
            params![reservation_hash, reserved_bytes, expires],
        )?;
        transaction.commit()?;
        Ok(UploadReservationExtendOutcome::Extended)
    }

    #[cfg(test)]
    pub fn commit_upload_reservation(
        &self,
        token: &str,
        uploaded_bytes: u64,
    ) -> rusqlite::Result<UploadReservationCommitOutcome> {
        self.commit_upload_reservation_internal(token, uploaded_bytes, None)
    }

    pub fn commit_upload_reservation_and_audit(
        &self,
        token: &str,
        uploaded_bytes: u64,
        context: &AuditContext,
    ) -> rusqlite::Result<UploadReservationCommitOutcome> {
        self.commit_upload_reservation_internal(token, uploaded_bytes, Some(context))
    }

    fn commit_upload_reservation_internal(
        &self,
        token: &str,
        uploaded_bytes: u64,
        required_audit: Option<&AuditContext>,
    ) -> rusqlite::Result<UploadReservationCommitOutcome> {
        let reservation_hash = token_hash(token);
        let now_text = Utc::now().to_rfc3339();
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM public_upload_reservations WHERE expires_at<=?1",
            [&now_text],
        )?;
        let reservation = transaction
            .query_row(
                "SELECT share_id,reserved_bytes,upload_policy_epoch
                 FROM public_upload_reservations
                 WHERE token_hash=?1",
                [&reservation_hash],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((share_id, reserved_bytes, upload_policy_epoch)) = reservation else {
            transaction.commit()?;
            return Ok(UploadReservationCommitOutcome::NotFound);
        };
        if available_upload_share_total_limit(
            &transaction,
            share_id,
            upload_policy_epoch,
            &now_text,
        )?
        .is_none()
        {
            transaction.execute(
                "DELETE FROM public_upload_reservations WHERE token_hash=?1",
                [&reservation_hash],
            )?;
            transaction.commit()?;
            return Ok(UploadReservationCommitOutcome::ShareUnavailable);
        }
        if uploaded_bytes > MAX_SQLITE_UNSIGNED {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if uploaded_bytes > reserved_bytes {
            return Err(rusqlite::Error::InvalidQuery);
        }
        transaction.execute(
            "INSERT INTO public_upload_usage(share_id,uploaded_bytes,uploaded_files)
             VALUES(?1,?2,1)
             ON CONFLICT(share_id) DO UPDATE SET
                 uploaded_bytes=uploaded_bytes+excluded.uploaded_bytes,
                 uploaded_files=uploaded_files+1",
            params![share_id, uploaded_bytes],
        )?;
        transaction.execute(
            "DELETE FROM public_upload_reservations WHERE token_hash=?1",
            [reservation_hash],
        )?;
        let audit_events = [RequiredAuditEvent::new(
            AuditAction::UploadQuotaCommitted,
            Some(share_id.to_string()),
            Some(format!("bytes={uploaded_bytes};files=1")),
        )];
        if let Some(context) = required_audit {
            insert_required_audits(&transaction, context, &audit_events)?;
        }
        transaction.commit()?;
        if let Some(context) = required_audit {
            trace_required_audits(context, &audit_events);
        }
        Ok(UploadReservationCommitOutcome::Committed)
    }

    pub fn cancel_upload_reservation(&self, token: &str) -> rusqlite::Result<bool> {
        Ok(self.try_conn()?.execute(
            "DELETE FROM public_upload_reservations WHERE token_hash=?1",
            [token_hash(token)],
        )? == 1)
    }

    #[cfg(test)]
    pub fn active_upload_reservations(&self, share_id: i64) -> rusqlite::Result<u64> {
        self.try_conn()?.query_row(
            "SELECT COUNT(*)
             FROM public_upload_reservations reservations
             JOIN shares ON shares.id=reservations.share_id
             WHERE reservations.share_id=?1 AND reservations.expires_at>?2
               AND reservations.upload_policy_epoch=shares.upload_policy_epoch",
            params![share_id, Utc::now().to_rfc3339()],
            |row| row.get(0),
        )
    }
    #[cfg(test)]
    pub fn count_download(&self, id: i64) -> rusqlite::Result<bool> {
        let now = Utc::now().to_rfc3339();
        Ok(self.try_conn()?.execute(
            "UPDATE shares
             SET download_count=download_count+1
             WHERE id=?1 AND active=1 AND (expires_at IS NULL OR expires_at>?2)
               AND (max_downloads IS NULL OR download_count + (
                    SELECT COUNT(*) FROM public_transfer_grants grants
                    WHERE grants.share_id=shares.id AND grants.counted=0
                      AND grants.expires_at>?2
                      AND EXISTS(
                          SELECT 1 FROM public_transfer_leases leases
                          WHERE leases.grant_id=grants.id AND leases.expires_at>?2
                      )
               ) < max_downloads)",
            params![id, now],
        )? == 1)
    }

    /// Starts one HTTP request lease for a route-scoped client transfer session.
    ///
    /// `session_token` is the client session cookie value. HTTP surfaces should use
    /// separate tokens (and cookie paths) when their sessions must not overlap.
    /// `resource_key` and `action` form the logical, count-once transfer identity.
    /// Each concrete request supplies a fresh `lease_token`.
    pub fn begin_transfer_lease(
        &self,
        session_token: &str,
        lease_token: &str,
        share_id: i64,
        resource_key: &str,
        action: &str,
    ) -> rusqlite::Result<TransferLeaseBeginOutcome> {
        let (now, expires) = transfer_deadlines();
        let session_token_hash = token_hash(session_token);
        let lease_token_hash = token_hash(lease_token);
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_transfer_state(&transaction, &now)?;
        let access = transfer_access_state(
            &transaction,
            &session_token_hash,
            share_id,
            resource_key,
            action,
            &now,
        )?;

        match access {
            TransferAccessState::ExistingGrant { grant_id, counted } => {
                if !counted {
                    transaction.execute(
                        "UPDATE public_transfer_grants SET expires_at=?2 WHERE id=?1",
                        params![grant_id, expires],
                    )?;
                }
                transaction.execute(
                    "INSERT INTO public_transfer_leases(token_hash,grant_id,created_at,heartbeat_at,expires_at)
                     VALUES(?1,?2,?3,?3,?4)",
                    params![lease_token_hash, grant_id, now, expires],
                )?;
                transaction.commit()?;
                return Ok(if counted {
                    TransferLeaseBeginOutcome::AlreadyCounted
                } else {
                    TransferLeaseBeginOutcome::NewLease
                });
            }
            TransferAccessState::LimitReached => {
                transaction.commit()?;
                return Ok(TransferLeaseBeginOutcome::LimitReached);
            }
            TransferAccessState::ShareUnavailable => {
                transaction.commit()?;
                return Ok(TransferLeaseBeginOutcome::ShareUnavailable);
            }
            TransferAccessState::Available => {}
        }

        transaction.execute(
            "INSERT INTO public_transfer_grants(
                session_token_hash,share_id,resource_key,action,counted,created_at,expires_at
             ) VALUES(?1,?2,?3,?4,0,?5,?6)",
            params![
                session_token_hash,
                share_id,
                resource_key,
                action,
                now,
                expires
            ],
        )?;
        let grant_id = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO public_transfer_leases(token_hash,grant_id,created_at,heartbeat_at,expires_at)
             VALUES(?1,?2,?3,?3,?4)",
            params![lease_token_hash, grant_id, now, expires],
        )?;
        transaction.commit()?;
        Ok(TransferLeaseBeginOutcome::NewLease)
    }

    /// Checks whether the same logical transfer could start without reserving or
    /// counting quota. This is used by bodyless HTTP methods such as HEAD.
    pub fn check_transfer_availability(
        &self,
        session_token: &str,
        share_id: i64,
        resource_key: &str,
        action: &str,
    ) -> rusqlite::Result<TransferAvailabilityOutcome> {
        let (now, _) = transfer_deadlines();
        let session_token_hash = token_hash(session_token);
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_transfer_state(&transaction, &now)?;
        let outcome = match transfer_access_state(
            &transaction,
            &session_token_hash,
            share_id,
            resource_key,
            action,
            &now,
        )? {
            TransferAccessState::Available => TransferAvailabilityOutcome::Available,
            TransferAccessState::ExistingGrant { counted: true, .. } => {
                TransferAvailabilityOutcome::AlreadyCounted
            }
            TransferAccessState::ExistingGrant { counted: false, .. } => {
                TransferAvailabilityOutcome::Available
            }
            TransferAccessState::LimitReached => TransferAvailabilityOutcome::LimitReached,
            TransferAccessState::ShareUnavailable => TransferAvailabilityOutcome::ShareUnavailable,
        };
        transaction.commit()?;
        Ok(outcome)
    }

    /// Completes one request lease. The first successful request for a pending
    /// grant increments the share counter; later requests for that grant do not.
    #[cfg(test)]
    pub fn complete_transfer_lease(
        &self,
        lease_token: &str,
    ) -> rusqlite::Result<TransferLeaseCompleteOutcome> {
        self.complete_transfer_lease_internal(lease_token, None)
    }

    pub fn complete_transfer_lease_and_audit(
        &self,
        lease_token: &str,
        context: &AuditContext,
        // Retained for HTTP-call-site compatibility. Audit authority comes from
        // the grant loaded below, never from these caller-provided hints.
        _caller_action: &'static str,
        _caller_share_id: i64,
    ) -> rusqlite::Result<TransferLeaseCompleteOutcome> {
        self.complete_transfer_lease_internal(lease_token, Some(context))
    }

    fn complete_transfer_lease_internal(
        &self,
        lease_token: &str,
        required_audit: Option<&AuditContext>,
    ) -> rusqlite::Result<TransferLeaseCompleteOutcome> {
        let (now, expires) = transfer_deadlines();
        let lease_token_hash = token_hash(lease_token);
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_transfer_state(&transaction, &now)?;
        let lease = transaction
            .query_row(
                "SELECT grants.id,grants.share_id,grants.counted,grants.action
                 FROM public_transfer_leases leases
                 JOIN public_transfer_grants grants ON grants.id=leases.grant_id
                 WHERE leases.token_hash=?1 AND leases.expires_at>?2 AND grants.expires_at>?2",
                params![lease_token_hash, now],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)? != 0,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((grant_id, share_id, already_counted, action)) = lease else {
            transaction.commit()?;
            return Ok(TransferLeaseCompleteOutcome::NotFound);
        };

        let outcome = if already_counted {
            TransferLeaseCompleteOutcome::AlreadyCounted
        } else {
            if transaction.execute(
                "UPDATE shares SET download_count=download_count+1 WHERE id=?1",
                [share_id],
            )? != 1
            {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            if transaction.execute(
                "UPDATE public_transfer_grants SET counted=1,expires_at=?2
                 WHERE id=?1 AND counted=0",
                params![grant_id, expires],
            )? != 1
            {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            let month = now.get(..7).ok_or(rusqlite::Error::InvalidQuery)?;
            increment_transfer_monthly_count(&transaction, month, &action)?;
            TransferLeaseCompleteOutcome::Counted
        };
        transaction.execute(
            "DELETE FROM public_transfer_leases WHERE token_hash=?1",
            [lease_token_hash],
        )?;
        let audit_events = match (outcome, required_audit) {
            (TransferLeaseCompleteOutcome::Counted, Some(_)) => {
                vec![RequiredAuditEvent::new(
                    required_transfer_audit_action(&action)?,
                    Some(share_id.to_string()),
                    Some("completed transfer session".into()),
                )]
            }
            _ => Vec::new(),
        };
        if let Some(context) = required_audit {
            insert_required_audits(&transaction, context, &audit_events)?;
        }
        transaction.commit()?;
        if let Some(context) = required_audit {
            trace_required_audits(context, &audit_events);
        }
        Ok(outcome)
    }

    /// Cancels only the specified request. A pending grant reservation is released
    /// when its final lease disappears; counted grants remain resumable until expiry.
    pub fn cancel_transfer_lease(
        &self,
        lease_token: &str,
    ) -> rusqlite::Result<TransferLeaseCancelOutcome> {
        let (now, _) = transfer_deadlines();
        let lease_token_hash = token_hash(lease_token);
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_transfer_state(&transaction, &now)?;
        let grant = transaction
            .query_row(
                "SELECT grants.id,grants.counted
                 FROM public_transfer_leases leases
                 JOIN public_transfer_grants grants ON grants.id=leases.grant_id
                 WHERE leases.token_hash=?1",
                [lease_token_hash.as_str()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)? != 0)),
            )
            .optional()?;
        let Some((grant_id, counted)) = grant else {
            transaction.commit()?;
            return Ok(TransferLeaseCancelOutcome::NotFound);
        };
        transaction.execute(
            "DELETE FROM public_transfer_leases WHERE token_hash=?1",
            [lease_token_hash],
        )?;
        if !counted {
            transaction.execute(
                "DELETE FROM public_transfer_grants
                 WHERE id=?1 AND counted=0
                   AND NOT EXISTS(SELECT 1 FROM public_transfer_leases WHERE grant_id=?1)",
                [grant_id],
            )?;
        }
        transaction.commit()?;
        Ok(TransferLeaseCancelOutcome::Cancelled)
    }

    #[cfg(test)]
    pub fn heartbeat_transfer_lease(
        &self,
        lease_token: &str,
    ) -> rusqlite::Result<TransferLeaseHeartbeatOutcome> {
        self.heartbeat_transfer_lease_internal(lease_token, None)
    }

    pub fn heartbeat_transfer_lease_and_audit(
        &self,
        lease_token: &str,
        context: &AuditContext,
    ) -> rusqlite::Result<TransferLeaseHeartbeatOutcome> {
        self.heartbeat_transfer_lease_internal(lease_token, Some(context))
    }

    fn heartbeat_transfer_lease_internal(
        &self,
        lease_token: &str,
        required_audit: Option<&AuditContext>,
    ) -> rusqlite::Result<TransferLeaseHeartbeatOutcome> {
        let now_datetime = Utc::now();
        let now = now_datetime.to_rfc3339();
        let rolling_expiry = now_datetime + Duration::seconds(TRANSFER_SESSION_TTL_SECONDS);
        let lease_token_hash = token_hash(lease_token);
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_transfer_state_before_heartbeat(&transaction, &now, &lease_token_hash)?;
        let grant = transaction
            .query_row(
                "SELECT leases.grant_id,grants.share_id,grants.counted,grants.action,
                        leases.created_at,leases.expires_at
                 FROM public_transfer_leases leases
                 JOIN public_transfer_grants grants ON grants.id=leases.grant_id
                 WHERE leases.token_hash=?1",
                [lease_token_hash.as_str()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)? != 0,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((grant_id, share_id, counted, action, created_at, lease_expires_at)) = grant
        else {
            cleanup_transfer_state(&transaction, &now)?;
            transaction.commit()?;
            return Ok(TransferLeaseHeartbeatOutcome::NotFound);
        };
        let created_at = DateTime::parse_from_rfc3339(&created_at)
            .map(|value| value.with_timezone(&Utc))
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    4,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
        let lease_expires_at = DateTime::parse_from_rfc3339(&lease_expires_at)
            .map(|value| value.with_timezone(&Utc))
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
        let absolute_expiry = created_at + Duration::seconds(TRANSFER_LEASE_MAX_LIFETIME_SECONDS);
        if absolute_expiry <= now_datetime {
            let outcome = if counted {
                TransferLeaseHeartbeatOutcome::CappedAlreadyCounted
            } else {
                if transaction.execute(
                    "UPDATE shares SET download_count=download_count+1 WHERE id=?1",
                    [share_id],
                )? != 1
                {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
                if transaction.execute(
                    "UPDATE public_transfer_grants SET counted=1,expires_at=?2
                     WHERE id=?1 AND counted=0",
                    params![grant_id, rolling_expiry.to_rfc3339()],
                )? != 1
                {
                    return Err(rusqlite::Error::QueryReturnedNoRows);
                }
                let month = now.get(..7).ok_or(rusqlite::Error::InvalidQuery)?;
                increment_transfer_monthly_count(&transaction, month, &action)?;
                TransferLeaseHeartbeatOutcome::CappedAndCounted
            };
            transaction.execute(
                "DELETE FROM public_transfer_leases WHERE token_hash=?1",
                [lease_token_hash],
            )?;
            cleanup_transfer_state(&transaction, &now)?;
            let audit_events = match (outcome, required_audit) {
                (TransferLeaseHeartbeatOutcome::CappedAndCounted, Some(_)) => {
                    vec![RequiredAuditEvent::new(
                        required_transfer_audit_action(&action)?,
                        Some(share_id.to_string()),
                        Some("capped transfer session".into()),
                    )]
                }
                _ => Vec::new(),
            };
            if let Some(context) = required_audit {
                insert_required_audits(&transaction, context, &audit_events)?;
            }
            transaction.commit()?;
            if let Some(context) = required_audit {
                trace_required_audits(context, &audit_events);
            }
            return Ok(outcome);
        }
        if lease_expires_at <= now_datetime {
            cleanup_transfer_state(&transaction, &now)?;
            transaction.commit()?;
            return Ok(TransferLeaseHeartbeatOutcome::NotFound);
        }
        let expires = std::cmp::min(rolling_expiry, absolute_expiry).to_rfc3339();
        transaction.execute(
            "UPDATE public_transfer_leases
             SET heartbeat_at=?2,expires_at=?3 WHERE token_hash=?1",
            params![lease_token_hash, now, expires],
        )?;
        if !counted {
            transaction.execute(
                "UPDATE public_transfer_grants
                 SET expires_at=(
                     SELECT MAX(expires_at) FROM public_transfer_leases WHERE grant_id=?1
                 )
                 WHERE id=?1",
                [grant_id],
            )?;
        }
        transaction.commit()?;
        Ok(TransferLeaseHeartbeatOutcome::Extended)
    }

    /// Number of distinct, uncounted grants currently reserving a download slot.
    pub fn active_transfer_reservations(&self, share_id: i64) -> rusqlite::Result<u64> {
        let now = Utc::now().to_rfc3339();
        self.try_conn()?.query_row(
            "SELECT COUNT(*) FROM public_transfer_grants grants
             WHERE grants.share_id=?1 AND grants.counted=0 AND grants.expires_at>?2
               AND EXISTS(
                   SELECT 1 FROM public_transfer_leases leases
                   WHERE leases.grant_id=grants.id AND leases.expires_at>?2
               )",
            params![share_id, now],
            |row| row.get(0),
        )
    }

    pub fn transfer_statistics_started_at(&self) -> rusqlite::Result<String> {
        self.try_conn()?.query_row(
            "SELECT started_at FROM transfer_statistics WHERE singleton=1",
            [],
            |row| row.get(0),
        )
    }
    pub fn transfer_monthly_counts(&self, month: &str) -> rusqlite::Result<TransferMonthlyCounts> {
        if !valid_utc_month(month) {
            return Err(rusqlite::Error::InvalidParameterName(
                "month must use UTC YYYY-MM".into(),
            ));
        }
        let connection = self.try_conn()?;
        let mut statement = connection.prepare(
            "SELECT action,count FROM transfer_monthly_counts WHERE month=?1 ORDER BY action",
        )?;
        let mut counts = TransferMonthlyCounts {
            month: month.to_string(),
            download: 0,
            zip_download: 0,
            preview: 0,
        };
        for row in statement.query_map([month], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        })? {
            let (action, count) = row?;
            match action.as_str() {
                "download" => counts.download = count,
                "zip_download" => counts.zip_download = count,
                "preview" => counts.preview = count,
                _ => return Err(rusqlite::Error::InvalidQuery),
            }
        }
        Ok(counts)
    }
    pub fn current_transfer_monthly_counts(&self) -> rusqlite::Result<TransferMonthlyCounts> {
        self.transfer_monthly_counts(&current_utc_month())
    }
}
