impl Database {
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
        let _write_guard = self.transfer_write_guard()?;
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
        let _write_guard = self.transfer_write_guard()?;
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
        let _write_guard = self.transfer_write_guard()?;
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
        let _write_guard = self.transfer_write_guard()?;
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
        let _write_guard = self.transfer_write_guard()?;
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
}
