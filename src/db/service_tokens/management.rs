impl Database {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_service_token_for_mfa_session(
        &self,
        proof: &MfaSessionProof,
        expected_password_hash: &str,
        name: &str,
        plaintext_token: &str,
        expires_at: Option<DateTime<Utc>>,
        context: &AuditContext,
    ) -> rusqlite::Result<SessionBound<Audited<ServiceTokenCreationOutcome>>> {
        if !valid_service_token_name(name) || !valid_service_token(plaintext_token) {
            return Err(rusqlite::Error::InvalidQuery);
        }

        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
            let now = Utc::now();
            if expires_at.is_some_and(|expires_at| expires_at <= now) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let now_string = now.to_rfc3339();
            let admin_id = proof.admin_id();
            let current_admin = transaction
                .query_row(
                    "SELECT username,password_hash FROM admins WHERE id=?1",
                    [admin_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            let Some((username, current_password_hash)) = current_admin else {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            };
            if current_password_hash != expected_password_hash {
                return Ok((
                    ServiceTokenCreationOutcome::ReauthenticationRejected,
                    vec![],
                ));
            }

            let name_exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM service_tokens WHERE name=?1 COLLATE NOCASE)",
                [name],
                |row| row.get(0),
            )?;
            if name_exists {
                return Ok((ServiceTokenCreationOutcome::NameConflict, vec![]));
            }
            let token_count: usize =
                transaction
                    .query_row("SELECT COUNT(*) FROM service_tokens", [], |row| row.get(0))?;
            if token_count >= MAX_SERVICE_TOKENS {
                return Ok((ServiceTokenCreationOutcome::CapacityReached, vec![]));
            }

            let expires_at_string = expires_at.map(|value| value.to_rfc3339());
            transaction.execute(
                "INSERT INTO service_tokens(
                     name,token_hash,scope_mask,created_by,created_at,expires_at,last_used_at
                 ) VALUES(?1,?2,1,?3,?4,?5,NULL)",
                params![
                    name,
                    token_hash(plaintext_token),
                    admin_id,
                    now_string,
                    expires_at_string,
                ],
            )?;
            let id = transaction.last_insert_rowid();
            let service_token = ServiceToken {
                id,
                name: name.to_owned(),
                scope_mask: super::SERVICE_TOKEN_SCOPE_MONITORING_READ,
                created_by: admin_id,
                created_by_username: username,
                created_at: now_string,
                expires_at: expires_at_string,
                last_used_at: None,
            };
            let audit_events = vec![RequiredAuditEvent::new(
                AuditAction::ServiceTokenCreated,
                Some(id.to_string()),
                Some("scope=monitoring:read".to_string()),
            )];
            Ok((
                ServiceTokenCreationOutcome::Created(service_token),
                audit_events,
            ))
        })
    }

    pub fn list_service_tokens(&self) -> rusqlite::Result<Vec<ServiceToken>> {
        let connection = self.try_conn()?;
        let mut statement = connection.prepare_cached(
            "SELECT tokens.id,tokens.name,tokens.scope_mask,tokens.created_by,
                    admins.username,tokens.created_at,tokens.expires_at,tokens.last_used_at
             FROM service_tokens tokens
             JOIN admins ON admins.id=tokens.created_by
             ORDER BY tokens.id DESC",
        )?;
        let tokens = statement
            .query_map([], map_service_token)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(tokens)
    }

    #[cfg(test)]
    pub(crate) fn expire_service_token_for_test(&self, id: i64) -> rusqlite::Result<()> {
        let connection = self.try_conn()?;
        let changed = connection.execute(
            "UPDATE service_tokens SET expires_at=?2 WHERE id=?1",
            params![id, (Utc::now() - Duration::seconds(1)).to_rfc3339()],
        )?;
        if changed != 1 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Ok(())
    }
}
