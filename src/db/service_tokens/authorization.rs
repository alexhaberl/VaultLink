impl Database {
    pub fn authorize_service_token(
        &self,
        plaintext_token: &str,
        required_scope_mask: i64,
    ) -> rusqlite::Result<ServiceTokenAuthorizationOutcome> {
        self.authorize_service_token_at(plaintext_token, required_scope_mask, Utc::now())
    }

    fn authorize_service_token_at(
        &self,
        plaintext_token: &str,
        required_scope_mask: i64,
        now: DateTime<Utc>,
    ) -> rusqlite::Result<ServiceTokenAuthorizationOutcome> {
        self.authorize_service_token_at_after_lookup(
            plaintext_token,
            required_scope_mask,
            now,
            || {},
        )
    }

    fn authorize_service_token_at_after_lookup<F>(
        &self,
        plaintext_token: &str,
        required_scope_mask: i64,
        now: DateTime<Utc>,
        after_authorized_lookup: F,
    ) -> rusqlite::Result<ServiceTokenAuthorizationOutcome>
    where
        F: FnOnce(),
    {
        if required_scope_mask <= 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if !valid_service_token(plaintext_token) {
            return Ok(ServiceTokenAuthorizationOutcome::Unauthorized);
        }
        let connection = self.try_conn()?;
        let token = connection
            .query_row(
                "SELECT id,scope_mask,expires_at,last_used_at
                 FROM service_tokens WHERE token_hash=?1",
                [token_hash(plaintext_token)],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, scope_mask, expires_at, last_used_at)) = token else {
            return Ok(ServiceTokenAuthorizationOutcome::Unauthorized);
        };
        let expires_at = parse_optional_timestamp(expires_at, 2)?;
        if expires_at.is_some_and(|expires_at| expires_at <= now) {
            return Ok(ServiceTokenAuthorizationOutcome::Unauthorized);
        }
        if scope_mask & required_scope_mask != required_scope_mask {
            return Ok(ServiceTokenAuthorizationOutcome::InsufficientScope);
        }

        let last_used_at = parse_optional_timestamp(last_used_at, 3)?;
        after_authorized_lookup();
        let cutoff = now - Duration::seconds(SERVICE_TOKEN_TOUCH_INTERVAL_SECONDS);
        if last_used_at.is_none_or(|last_used_at| last_used_at <= cutoff) {
            // Revocation may linearize between the read and this throttled
            // metadata write. That request was already authorized; the guarded
            // update cannot resurrect it and every subsequent lookup fails.
            connection.execute(
                "UPDATE service_tokens SET last_used_at=?2
                 WHERE id=?1
                   AND (expires_at IS NULL OR expires_at>?2)
                   AND (last_used_at IS NULL OR last_used_at<=?3)",
                params![id, now.to_rfc3339(), cutoff.to_rfc3339()],
            )?;
        }
        Ok(ServiceTokenAuthorizationOutcome::Authorized { token_id: id })
    }

    pub(crate) fn revoke_service_token_for_mfa_session(
        &self,
        proof: &MfaSessionProof,
        id: i64,
        context: &AuditContext,
    ) -> rusqlite::Result<SessionBound<Audited<bool>>> {
        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
            let exists = transaction
                .query_row("SELECT 1 FROM service_tokens WHERE id=?1", [id], |row| {
                    row.get::<_, i64>(0)
                })
                .optional()?
                .is_some();
            if !exists {
                return Ok((false, vec![]));
            }
            let deleted = transaction.execute("DELETE FROM service_tokens WHERE id=?1", [id])?;
            if deleted != 1 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok((
                true,
                vec![RequiredAuditEvent::new(
                    AuditAction::ServiceTokenRevoked,
                    Some(id.to_string()),
                    None,
                )],
            ))
        })
    }

    pub fn revoke_all_service_tokens_and_audit(
        &self,
        context: &AuditContext,
    ) -> rusqlite::Result<usize> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let deleted = transaction.execute("DELETE FROM service_tokens", [])?;
        let audit_events = [RequiredAuditEvent::new(
            AuditAction::ServiceTokensRevokedAll,
            None,
            Some(format!("count={deleted}")),
        )];
        insert_required_audits(&transaction, context, &audit_events)?;
        transaction.commit()?;
        trace_required_audits(context, &audit_events);
        Ok(deleted)
    }
}
