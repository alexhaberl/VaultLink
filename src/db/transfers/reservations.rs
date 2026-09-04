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
        let _write_guard = self.transfer_write_guard()?;
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
        let _write_guard = self.transfer_write_guard()?;
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

    pub(crate) fn commit_upload_reservation_and_audit_audited(
        &self,
        token: &str,
        uploaded_bytes: u64,
        context: &AuditContext,
    ) -> rusqlite::Result<Audited<UploadReservationCommitOutcome>> {
        self.commit_upload_reservation_internal(token, uploaded_bytes, Some(context))
            .map(Audited::new)
    }

    fn commit_upload_reservation_internal(
        &self,
        token: &str,
        uploaded_bytes: u64,
        required_audit: Option<&AuditContext>,
    ) -> rusqlite::Result<UploadReservationCommitOutcome> {
        let reservation_hash = token_hash(token);
        let now_text = Utc::now().to_rfc3339();
        let _write_guard = self.transfer_write_guard()?;
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
        let _write_guard = self.transfer_write_guard()?;
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
        let _write_guard = self.transfer_write_guard()?;
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
}
