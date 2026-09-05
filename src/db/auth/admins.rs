impl Database {
    #[cfg(test)]
    pub fn create_initial_admin(
        &self,
        username: &str,
        password_hash: &str,
        totp_secret: &str,
    ) -> rusqlite::Result<InitialAdminOutcome> {
        let (totp_key_id, totp_ciphertext) = self.encrypt_admin_totp(username, totp_secret)?;
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let initialized: bool =
            transaction.query_row("SELECT EXISTS(SELECT 1 FROM admins)", [], |row| row.get(0))?;
        let outcome = if initialized {
            InitialAdminOutcome::AlreadyInitialized
        } else {
            transaction.execute(
                "INSERT INTO admins(username,password_hash,totp_key_id,totp_ciphertext,created_at,active) VALUES(?1,?2,?3,?4,?5,1)",
                params![username, password_hash, totp_key_id, totp_ciphertext, Utc::now().to_rfc3339()],
            )?;
            InitialAdminOutcome::Created
        };
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn create_initial_admin_and_audit(
        &self,
        username: &str,
        password_hash: &str,
        totp_secret: &str,
        context: &AuditContext,
    ) -> rusqlite::Result<InitialAdminOutcome> {
        let (totp_key_id, totp_ciphertext) = self.encrypt_admin_totp(username, totp_secret)?;
        self.required_transaction(context, |transaction| {
            let initialized: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM admins)",
                [],
                |row| row.get(0),
            )?;
            if initialized {
                return Ok((InitialAdminOutcome::AlreadyInitialized, Vec::new()));
            }
            transaction.execute(
                "INSERT INTO admins(username,password_hash,totp_key_id,totp_ciphertext,created_at,active) VALUES(?1,?2,?3,?4,?5,1)",
                params![username, password_hash, totp_key_id, totp_ciphertext, Utc::now().to_rfc3339()],
            )?;
            let admin_id = transaction.last_insert_rowid();
            Ok((
                InitialAdminOutcome::Created,
                vec![RequiredAuditEvent::new(
                    AuditAction::InitialAdminCreated,
                    Some(admin_id.to_string()),
                    None,
                )],
            ))
        })
    }

    #[cfg(test)]
    pub fn create_admin(
        &self,
        username: &str,
        password_hash: &str,
        totp_secret: &str,
    ) -> rusqlite::Result<()> {
        let (totp_key_id, totp_ciphertext) = self.encrypt_admin_totp(username, totp_secret)?;
        self.try_conn()?.execute(
            "INSERT INTO admins(username,password_hash,totp_key_id,totp_ciphertext,created_at,active) VALUES(?1,?2,?3,?4,?5,1)",
            params![
                username,
                password_hash,
                totp_key_id,
                totp_ciphertext,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn create_admin_and_audit(
        &self,
        username: &str,
        password_hash: &str,
        totp_secret: &str,
        context: &AuditContext,
    ) -> rusqlite::Result<AdminSummary> {
        let (totp_key_id, totp_ciphertext) = self.encrypt_admin_totp(username, totp_secret)?;
        self.required_transaction(context, |transaction| {
            let created_at = Utc::now().to_rfc3339();
            transaction.execute(
                "INSERT INTO admins(username,password_hash,totp_key_id,totp_ciphertext,created_at,active)
                 VALUES(?1,?2,?3,?4,?5,1)",
                params![username, password_hash, totp_key_id, totp_ciphertext, &created_at],
            )?;
            let id = transaction.last_insert_rowid();
            let admin = AdminSummary {
                id,
                username: username.to_string(),
                created_at,
                active: true,
            };
            Ok((
                admin,
                vec![RequiredAuditEvent::new(
                    AuditAction::AdminCreated,
                    Some(id.to_string()),
                    None,
                )],
            ))
        })
    }

    pub(crate) fn create_admin_and_audit_for_session(
        &self,
        proof: &MfaSessionProof,
        username: &str,
        password_hash: &str,
        totp_secret: &str,
        context: &AuditContext,
    ) -> rusqlite::Result<SessionBound<Audited<AdminSummary>>> {
        let (totp_key_id, totp_ciphertext) = self.encrypt_admin_totp(username, totp_secret)?;
        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
            let created_at = Utc::now().to_rfc3339();
            transaction.execute(
                "INSERT INTO admins(username,password_hash,totp_key_id,totp_ciphertext,created_at,active)
                 VALUES(?1,?2,?3,?4,?5,1)",
                params![username, password_hash, totp_key_id, totp_ciphertext, &created_at],
            )?;
            let id = transaction.last_insert_rowid();
            let admin = AdminSummary {
                id,
                username: username.to_string(),
                created_at,
                active: true,
            };
            Ok((
                admin,
                vec![RequiredAuditEvent::new(
                    AuditAction::AdminCreated,
                    Some(id.to_string()),
                    None,
                )],
            ))
        })
    }
    pub fn admin(&self, username: &str) -> rusqlite::Result<Option<Admin>> {
        self.try_conn()?
            .query_row(
                "SELECT id,username,password_hash,totp_key_id,totp_ciphertext,totp_generation,totp_enabled,active FROM admins WHERE username=?1 AND active=1",
                [username],
                |r| {
                    let canonical_username: String = r.get(1)?;
                    let key_id = r.get(3)?;
                    let ciphertext: Vec<u8> = r.get(4)?;
                    Ok(Admin {
                        id: r.get(0)?,
                        username: canonical_username.clone(),
                        password_hash: r.get(2)?,
                        totp_secret: self.decrypt_admin_totp(&canonical_username, key_id, &ciphertext)?,
                        totp_generation: r.get(5)?,
                        totp_enabled: r.get::<_, i64>(6)? != 0,
                        active: r.get::<_, i64>(7)? != 0,
                    })
                },
            )
            .optional()
    }
    pub fn admin_count(&self) -> rusqlite::Result<i64> {
        self.try_conn()?
            .query_row("SELECT COUNT(*) FROM admins", [], |row| row.get(0))
    }
    pub fn active_admin_count(&self) -> rusqlite::Result<i64> {
        self.try_conn()?
            .query_row("SELECT COUNT(*) FROM admins WHERE active=1", [], |row| {
                row.get(0)
            })
    }
    pub fn active_admin_usernames(&self) -> rusqlite::Result<Vec<String>> {
        let connection = self.try_conn()?;
        active_admin_usernames_on_connection(&connection)
    }
    pub fn list_admins(&self) -> rusqlite::Result<Vec<AdminSummary>> {
        let c = self.try_conn()?;
        let mut statement =
            c.prepare("SELECT id,username,created_at,active FROM admins ORDER BY id ASC")?;
        let admins = statement
            .query_map([], |row| {
                Ok(AdminSummary {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    created_at: row.get(2)?,
                    active: row.get::<_, i64>(3)? != 0,
                })
            })?
            .collect();
        admins
    }
    #[cfg(test)]
    pub fn activate_admin(&self, id: i64) -> rusqlite::Result<bool> {
        Ok(self
            .try_conn()?
            .execute("UPDATE admins SET active=1 WHERE id=?1", [id])?
            == 1)
    }

    #[cfg(test)]
    pub fn activate_admin_and_audit(
        &self,
        id: i64,
        context: &AuditContext,
    ) -> rusqlite::Result<bool> {
        self.required_transaction(context, |transaction| {
            let changed = transaction.execute("UPDATE admins SET active=1 WHERE id=?1", [id])? == 1;
            let events = changed
                .then(|| {
                    RequiredAuditEvent::new(AuditAction::AdminActivated, Some(id.to_string()), None)
                })
                .into_iter()
                .collect();
            Ok((changed, events))
        })
    }

    pub(crate) fn activate_admin_and_audit_for_session(
        &self,
        proof: &MfaSessionProof,
        id: i64,
        context: &AuditContext,
    ) -> rusqlite::Result<SessionBound<Audited<bool>>> {
        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
            let changed = transaction.execute("UPDATE admins SET active=1 WHERE id=?1", [id])? == 1;
            let events = changed
                .then(|| {
                    RequiredAuditEvent::new(AuditAction::AdminActivated, Some(id.to_string()), None)
                })
                .into_iter()
                .collect();
            Ok((changed, events))
        })
    }

    #[cfg(test)]
    pub fn deactivate_admin(&self, id: i64) -> rusqlite::Result<AdminDeactivationOutcome> {
        self.deactivate_admin_internal(id, None)
    }

    #[cfg(test)]
    pub fn deactivate_admin_and_audit(
        &self,
        id: i64,
        context: &AuditContext,
    ) -> rusqlite::Result<AdminDeactivationOutcome> {
        self.deactivate_admin_internal(id, Some(context))
    }

    pub(crate) fn deactivate_admin_and_audit_for_session(
        &self,
        proof: &MfaSessionProof,
        id: i64,
        context: &AuditContext,
    ) -> rusqlite::Result<SessionBound<Audited<AdminDeactivationOutcome>>> {
        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
            let active = transaction
                .query_row("SELECT active FROM admins WHERE id=?1", [id], |row| {
                    row.get::<_, i64>(0).map(|active| active != 0)
                })
                .optional()?;
            let outcome = match active {
                None => AdminDeactivationOutcome::NotFound,
                Some(false) => {
                    revoke_admin_auth_state(transaction, id)?;
                    AdminDeactivationOutcome::AlreadyInactive
                }
                Some(true) => {
                    let changed = transaction.execute(
                        "UPDATE admins SET active=0
                         WHERE id=?1 AND active=1
                           AND EXISTS(SELECT 1 FROM admins WHERE active=1 AND id<>?1)",
                        [id],
                    )? == 1;
                    if changed {
                        revoke_admin_auth_state(transaction, id)?;
                        AdminDeactivationOutcome::Deactivated
                    } else {
                        AdminDeactivationOutcome::LastActive
                    }
                }
            };
            let events = matches!(
                outcome,
                AdminDeactivationOutcome::Deactivated | AdminDeactivationOutcome::AlreadyInactive
            )
            .then(|| {
                RequiredAuditEvent::new(AuditAction::AdminDeactivated, Some(id.to_string()), None)
            })
            .into_iter()
            .collect();
            Ok((outcome, events))
        })
    }

    #[cfg(test)]
    fn deactivate_admin_internal(
        &self,
        id: i64,
        required_audit: Option<&AuditContext>,
    ) -> rusqlite::Result<AdminDeactivationOutcome> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active = transaction
            .query_row("SELECT active FROM admins WHERE id=?1", [id], |row| {
                row.get::<_, i64>(0).map(|active| active != 0)
            })
            .optional()?;
        let outcome = match active {
            None => AdminDeactivationOutcome::NotFound,
            Some(false) => {
                // Preserve the session-revocation invariant even if an older database
                // somehow contains sessions for an already inactive administrator.
                revoke_admin_auth_state(&transaction, id)?;
                AdminDeactivationOutcome::AlreadyInactive
            }
            Some(true) => {
                let changed = transaction.execute(
                    "UPDATE admins SET active=0
                     WHERE id=?1 AND active=1
                       AND EXISTS(SELECT 1 FROM admins WHERE active=1 AND id<>?1)",
                    [id],
                )? == 1;
                if changed {
                    revoke_admin_auth_state(&transaction, id)?;
                    AdminDeactivationOutcome::Deactivated
                } else {
                    AdminDeactivationOutcome::LastActive
                }
            }
        };
        let audit_events = matches!(
            outcome,
            AdminDeactivationOutcome::Deactivated | AdminDeactivationOutcome::AlreadyInactive
        )
        .then(|| {
            vec![RequiredAuditEvent::new(
                AuditAction::AdminDeactivated,
                Some(id.to_string()),
                None,
            )]
        })
        .unwrap_or_default();
        if let Some(context) = required_audit {
            insert_required_audits(&transaction, context, &audit_events)?;
        }
        transaction.commit()?;
        if let Some(context) = required_audit {
            trace_required_audits(context, &audit_events);
        }
        Ok(outcome)
    }

    /// Applies a local operator recovery as one credential/session/audit transaction.
    /// Credential values are deliberately excluded from the persisted and tracing audit data.
    pub fn recover_admin(
        &self,
        username: &str,
        password_hash: Option<&str>,
        totp_secret: Option<&str>,
    ) -> rusqlite::Result<AdminRecoveryOutcome> {
        if password_hash.is_none() && totp_secret.is_none() {
            return Err(rusqlite::Error::InvalidParameterName(
                "password_hash or totp_secret".into(),
            ));
        }
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let admin = transaction
            .query_row(
                "SELECT id,username,active FROM admins WHERE username=?1",
                [username],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)? != 0,
                    ))
                },
            )
            .optional()?;
        let Some((admin_id, canonical_username, active)) = admin else {
            transaction.commit()?;
            return Ok(AdminRecoveryOutcome::NotFound);
        };
        let encrypted_totp = totp_secret
            .map(|secret| self.encrypt_admin_totp(&canonical_username, secret))
            .transpose()?;
        let totp_key_id = encrypted_totp.as_ref().map(|value| value.0);
        let totp_ciphertext = encrypted_totp.as_ref().map(|value| value.1.as_slice());
        transaction.execute(
            "UPDATE admins
             SET password_hash=COALESCE(?2,password_hash),
                 totp_key_id=COALESCE(?3,totp_key_id),
                 totp_ciphertext=COALESCE(?4,totp_ciphertext),
                 totp_generation=totp_generation+CASE WHEN ?3 IS NULL THEN 0 ELSE 1 END,
                 totp_enabled=CASE WHEN ?3 IS NULL THEN totp_enabled ELSE 1 END
             WHERE id=?1",
            params![admin_id, password_hash, totp_key_id, totp_ciphertext],
        )?;
        if totp_secret.is_some() {
            transaction.execute(
                "DELETE FROM admin_webauthn_credentials WHERE admin_id=?1",
                [admin_id],
            )?;
            transaction.execute(
                "DELETE FROM admin_totp_replay WHERE admin_id=?1",
                [admin_id],
            )?;
        }
        revoke_admin_auth_state(&transaction, admin_id)?;
        let object_id = admin_id.to_string();
        let detail = format!(
            "reset_password={};reset_mfa={}",
            password_hash.is_some(),
            totp_secret.is_some()
        );
        let audit_context = AuditContext::new("local_recovery", None);
        let audit_events = [RequiredAuditEvent::new(
            AuditAction::AdminRecovered,
            Some(object_id.clone()),
            Some(detail),
        )];
        insert_required_audits(&transaction, &audit_context, &audit_events)?;
        transaction.commit()?;
        trace_required_audits(&audit_context, &audit_events);
        tracing::warn!(
            target: "vaultlink::audit",
            actor = "local_recovery",
            action = "admin_recovered",
            object_id = %crate::log_safety::EscapedLogValue::new(&object_id),
            username = %crate::log_safety::EscapedLogValue::new(&canonical_username),
            reset_password = password_hash.is_some(),
            reset_mfa = totp_secret.is_some(),
            "local administrator recovery completed"
        );
        Ok(AdminRecoveryOutcome::Recovered {
            admin_id,
            username: canonical_username,
            active,
        })
    }

    /// Changes an administrator password only if the hash verified by the caller is still current.
    #[cfg(test)]
    pub fn change_admin_password_cas(
        &self,
        id: i64,
        expected_password_hash: &str,
        new_password_hash: &str,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<AdminPasswordChangeOutcome> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let admin = transaction
            .query_row(
                "SELECT username,password_hash,active FROM admins WHERE id=?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)? != 0,
                    ))
                },
            )
            .optional()?;
        let Some((username, current_password_hash, active)) = admin else {
            transaction.commit()?;
            return Ok(AdminPasswordChangeOutcome::NotFound);
        };
        if !active {
            transaction.commit()?;
            return Ok(AdminPasswordChangeOutcome::Inactive);
        }
        if current_password_hash != expected_password_hash {
            transaction.commit()?;
            return Ok(AdminPasswordChangeOutcome::StalePassword);
        }
        let changed = transaction.execute(
            "UPDATE admins SET password_hash=?3 WHERE id=?1 AND password_hash=?2",
            params![id, expected_password_hash, new_password_hash],
        )?;
        if changed != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        revoke_admin_auth_state(&transaction, id)?;
        let object_id = id.to_string();
        let audit_context = AuditContext::new(&username, client_ip.map(str::to_string));
        let audit_events = [RequiredAuditEvent::new(
            AuditAction::AccountPasswordChanged,
            Some(object_id),
            None,
        )];
        insert_required_audits(&transaction, &audit_context, &audit_events)?;
        transaction.commit()?;
        trace_required_audits(&audit_context, &audit_events);
        Ok(AdminPasswordChangeOutcome::Changed)
    }

    pub(crate) fn change_admin_password_cas_for_session(
        &self,
        proof: &MfaSessionProof,
        expected_password_hash: &str,
        new_password_hash: &str,
        context: &AuditContext,
    ) -> rusqlite::Result<SessionBound<Audited<AdminPasswordChangeOutcome>>> {
        let id = proof.admin_id();
        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
            let admin = transaction
                .query_row(
                    "SELECT password_hash,active FROM admins WHERE id=?1",
                    [id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0)),
                )
                .optional()?;
            let Some((current_password_hash, active)) = admin else {
                return Ok((AdminPasswordChangeOutcome::NotFound, Vec::new()));
            };
            if !active {
                return Ok((AdminPasswordChangeOutcome::Inactive, Vec::new()));
            }
            if current_password_hash != expected_password_hash {
                return Ok((AdminPasswordChangeOutcome::StalePassword, Vec::new()));
            }
            let changed = transaction.execute(
                "UPDATE admins SET password_hash=?3 WHERE id=?1 AND password_hash=?2",
                params![id, expected_password_hash, new_password_hash],
            )?;
            if changed != 1 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            revoke_admin_auth_state(transaction, id)?;
            Ok((
                AdminPasswordChangeOutcome::Changed,
                vec![RequiredAuditEvent::new(
                    AuditAction::AccountPasswordChanged,
                    Some(id.to_string()),
                    None,
                )],
            ))
        })
    }
}
