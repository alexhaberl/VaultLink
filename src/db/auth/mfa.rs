impl Database {
    /// Starts or replaces one short-lived enrollment. Only a hash of `token` is persisted.
    #[cfg(test)]
    pub fn start_admin_mfa_enrollment(
        &self,
        admin_id: i64,
        token: &str,
        totp_secret: &str,
    ) -> rusqlite::Result<AdminMfaEnrollmentStartOutcome> {
        let now = Utc::now();
        let now_string = now.to_rfc3339();
        let expires_at = (now + Duration::seconds(ADMIN_MFA_ENROLLMENT_TTL_SECONDS)).to_rfc3339();
        let enrollment_token_hash = token_hash(token);
        let (totp_key_id, totp_ciphertext) =
            self.encrypt_enrollment_totp(&enrollment_token_hash, totp_secret)?;
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_admin_mfa_enrollments(&transaction, &now_string)?;
        let active = transaction
            .query_row("SELECT active FROM admins WHERE id=?1", [admin_id], |row| {
                row.get::<_, i64>(0).map(|active| active != 0)
            })
            .optional()?;
        match active {
            None => {
                transaction.commit()?;
                return Ok(AdminMfaEnrollmentStartOutcome::AdminNotFound);
            }
            Some(false) => {
                transaction.commit()?;
                return Ok(AdminMfaEnrollmentStartOutcome::AdminInactive);
            }
            Some(true) => {}
        }
        transaction.execute(
            "INSERT INTO admin_mfa_enrollments(
                 admin_id,token_hash,totp_key_id,totp_ciphertext,created_at,expires_at
             ) VALUES(?1,?2,?3,?4,?5,?6)
             ON CONFLICT(admin_id) DO UPDATE SET
                 token_hash=excluded.token_hash,
                 totp_key_id=excluded.totp_key_id,
                 totp_ciphertext=excluded.totp_ciphertext,
                 created_at=excluded.created_at,
                 expires_at=excluded.expires_at",
            params![
                admin_id,
                enrollment_token_hash,
                totp_key_id,
                totp_ciphertext,
                now_string,
                expires_at
            ],
        )?;
        transaction.commit()?;
        Ok(AdminMfaEnrollmentStartOutcome::Started { expires_at })
    }

    /// Atomically consumes the current TOTP counter, starts a pending enrollment,
    /// and persists the required audit event. An audit failure rolls all three
    /// mutations back, including the replay counter update.
    #[cfg(test)]
    pub fn start_admin_mfa_enrollment_and_audit(
        &self,
        admin_id: i64,
        token: &str,
        totp_secret: &str,
        verified_totp_step: u64,
        context: &AuditContext,
    ) -> rusqlite::Result<AuditedAdminMfaEnrollmentStartOutcome> {
        let now = Utc::now();
        let now_string = now.to_rfc3339();
        let expires_at = (now + Duration::seconds(ADMIN_MFA_ENROLLMENT_TTL_SECONDS)).to_rfc3339();
        let enrollment_token_hash = token_hash(token);
        let (totp_key_id, totp_ciphertext) =
            self.encrypt_enrollment_totp(&enrollment_token_hash, totp_secret)?;
        self.required_transaction(context, |transaction| {
            cleanup_admin_mfa_enrollments(transaction, &now_string)?;
            let active = transaction
                .query_row("SELECT active FROM admins WHERE id=?1", [admin_id], |row| {
                    row.get::<_, i64>(0).map(|active| active != 0)
                })
                .optional()?;
            match active {
                None => {
                    return Ok((
                        AuditedAdminMfaEnrollmentStartOutcome::AdminNotFound,
                        Vec::new(),
                    ));
                }
                Some(false) => {
                    return Ok((
                        AuditedAdminMfaEnrollmentStartOutcome::AdminInactive,
                        Vec::new(),
                    ));
                }
                Some(true) => {}
            }
            if !consume_admin_totp_step(transaction, admin_id, verified_totp_step)? {
                return Ok((
                    AuditedAdminMfaEnrollmentStartOutcome::TotpRejected,
                    Vec::new(),
                ));
            }
            transaction.execute(
                "INSERT INTO admin_mfa_enrollments(
                     admin_id,token_hash,totp_key_id,totp_ciphertext,created_at,expires_at
                 ) VALUES(?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(admin_id) DO UPDATE SET
                     token_hash=excluded.token_hash,
                     totp_key_id=excluded.totp_key_id,
                     totp_ciphertext=excluded.totp_ciphertext,
                     created_at=excluded.created_at,
                     expires_at=excluded.expires_at",
                params![
                    admin_id,
                    enrollment_token_hash,
                    totp_key_id,
                    totp_ciphertext,
                    now_string,
                    expires_at
                ],
            )?;
            Ok((
                AuditedAdminMfaEnrollmentStartOutcome::Started { expires_at },
                vec![RequiredAuditEvent::new(
                    AuditAction::AccountMfaEnrollmentStarted,
                    Some(admin_id.to_string()),
                    None,
                )],
            ))
        })
    }

    pub(crate) fn start_admin_mfa_enrollment_and_audit_for_session(
        &self,
        proof: &MfaSessionProof,
        token: &str,
        totp_secret: &str,
        verified_totp_step: u64,
        context: &AuditContext,
    ) -> rusqlite::Result<SessionBound<Audited<AuditedAdminMfaEnrollmentStartOutcome>>> {
        let enrollment_token_hash = token_hash(token);
        let (totp_key_id, totp_ciphertext) =
            self.encrypt_enrollment_totp(&enrollment_token_hash, totp_secret)?;
        let admin_id = proof.admin_id();
        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
            let now = Utc::now();
            let now_string = now.to_rfc3339();
            let expires_at =
                (now + Duration::seconds(ADMIN_MFA_ENROLLMENT_TTL_SECONDS)).to_rfc3339();
            cleanup_admin_mfa_enrollments(transaction, &now_string)?;
            if !consume_admin_totp_step(transaction, admin_id, verified_totp_step)? {
                return Ok((
                    AuditedAdminMfaEnrollmentStartOutcome::TotpRejected,
                    Vec::new(),
                ));
            }
            transaction.execute(
                "INSERT INTO admin_mfa_enrollments(
                     admin_id,token_hash,totp_key_id,totp_ciphertext,created_at,expires_at
                 ) VALUES(?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(admin_id) DO UPDATE SET
                     token_hash=excluded.token_hash,
                     totp_key_id=excluded.totp_key_id,
                     totp_ciphertext=excluded.totp_ciphertext,
                     created_at=excluded.created_at,
                     expires_at=excluded.expires_at",
                params![
                    admin_id,
                    enrollment_token_hash,
                    totp_key_id,
                    totp_ciphertext,
                    now_string,
                    expires_at
                ],
            )?;
            Ok((
                AuditedAdminMfaEnrollmentStartOutcome::Started { expires_at },
                vec![RequiredAuditEvent::new(
                    AuditAction::AccountMfaEnrollmentStarted,
                    Some(admin_id.to_string()),
                    None,
                )],
            ))
        })
    }

    /// Returns a pending secret only to a caller presenting the raw enrollment token.
    pub fn admin_mfa_enrollment(
        &self,
        admin_id: i64,
        token: &str,
    ) -> rusqlite::Result<Option<PendingAdminMfaEnrollment>> {
        let now = Utc::now().to_rfc3339();
        let enrollment_token_hash = token_hash(token);
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_admin_mfa_enrollments(&transaction, &now)?;
        let enrollment = transaction
            .query_row(
                "SELECT admin_mfa_enrollments.admin_id,
                        admin_mfa_enrollments.totp_key_id,
                        admin_mfa_enrollments.totp_ciphertext,
                        admin_mfa_enrollments.expires_at
                 FROM admin_mfa_enrollments
                 JOIN admins ON admins.id=admin_mfa_enrollments.admin_id
                 WHERE admin_mfa_enrollments.admin_id=?1
                   AND admin_mfa_enrollments.token_hash=?2
                   AND admin_mfa_enrollments.expires_at>?3
                   AND admins.active=1",
                params![admin_id, enrollment_token_hash, now],
                |row| {
                    Ok(PendingAdminMfaEnrollment {
                        admin_id: row.get(0)?,
                        totp_secret: self.decrypt_enrollment_totp(
                            &enrollment_token_hash,
                            row.get(1)?,
                            &row.get::<_, Vec<u8>>(2)?,
                        )?,
                        expires_at: row.get(3)?,
                    })
                },
            )
            .optional()?;
        transaction.commit()?;
        Ok(enrollment)
    }

    /// Activates and consumes an enrollment after the caller verified a code against its secret.
    /// The secret is never included in the audit event.
    #[cfg(test)]
    pub fn activate_admin_mfa_enrollment(
        &self,
        admin_id: i64,
        token: &str,
        verified_totp_step: u64,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<AdminMfaEnrollmentActivationOutcome> {
        if verified_totp_step > i64::MAX as u64 {
            return Err(rusqlite::Error::InvalidParameterName(
                "verified_totp_step".into(),
            ));
        }
        let now = Utc::now().to_rfc3339();
        let enrollment_token_hash = token_hash(token);
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_admin_mfa_enrollments(&transaction, &now)?;
        let enrollment = transaction
            .query_row(
                "SELECT admins.username,admin_mfa_enrollments.totp_key_id,
                        admin_mfa_enrollments.totp_ciphertext
                 FROM admin_mfa_enrollments
                 JOIN admins ON admins.id=admin_mfa_enrollments.admin_id
                 WHERE admin_mfa_enrollments.admin_id=?1
                   AND admin_mfa_enrollments.token_hash=?2
                   AND admin_mfa_enrollments.expires_at>?3
                   AND admins.active=1",
                params![admin_id, enrollment_token_hash, now],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((username, enrollment_key_id, enrollment_ciphertext)) = enrollment else {
            transaction.commit()?;
            return Ok(AdminMfaEnrollmentActivationOutcome::NotFoundOrExpired);
        };
        let totp_secret = self.decrypt_enrollment_totp(
            &enrollment_token_hash,
            enrollment_key_id,
            &enrollment_ciphertext,
        )?;
        let (totp_key_id, totp_ciphertext) =
            self.encrypt_admin_totp(&username, totp_secret.expose_secret())?;
        transaction.execute(
            "UPDATE admins SET totp_key_id=?2,totp_ciphertext=?3,
                 totp_generation=totp_generation+1,totp_enabled=1 WHERE id=?1",
            params![admin_id, totp_key_id, totp_ciphertext],
        )?;
        transaction.execute(
            "INSERT INTO admin_totp_replay(admin_id,last_step) VALUES(?1,?2)
             ON CONFLICT(admin_id) DO UPDATE SET last_step=excluded.last_step",
            params![admin_id, verified_totp_step as i64],
        )?;
        revoke_admin_auth_state(&transaction, admin_id)?;
        let object_id = admin_id.to_string();
        let audit_context = AuditContext::new(&username, client_ip.map(str::to_string));
        let audit_events = [RequiredAuditEvent::new(
            AuditAction::AccountMfaChanged,
            Some(object_id),
            None,
        )];
        insert_required_audits(&transaction, &audit_context, &audit_events)?;
        transaction.commit()?;
        trace_required_audits(&audit_context, &audit_events);
        Ok(AdminMfaEnrollmentActivationOutcome::Activated)
    }

    pub(crate) fn activate_admin_mfa_enrollment_for_session(
        &self,
        proof: &MfaSessionProof,
        token: &str,
        verified_totp_step: u64,
        context: &AuditContext,
    ) -> rusqlite::Result<SessionBound<Audited<AdminMfaEnrollmentActivationOutcome>>> {
        if verified_totp_step > i64::MAX as u64 {
            return Err(rusqlite::Error::InvalidParameterName(
                "verified_totp_step".into(),
            ));
        }
        let enrollment_token_hash = token_hash(token);
        let admin_id = proof.admin_id();
        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
            // Capture time only after BEGIN IMMEDIATE has acquired the writer
            // slot. A request that waited behind another mutation must not
            // activate an enrollment which expired while it was queued.
            let now = Utc::now().to_rfc3339();
            cleanup_admin_mfa_enrollments(transaction, &now)?;
            let enrollment = transaction
                .query_row(
                    "SELECT admins.username,admin_mfa_enrollments.totp_key_id,
                            admin_mfa_enrollments.totp_ciphertext
                     FROM admin_mfa_enrollments
                     JOIN admins ON admins.id=admin_mfa_enrollments.admin_id
                     WHERE admin_mfa_enrollments.admin_id=?1
                       AND admin_mfa_enrollments.token_hash=?2
                       AND admin_mfa_enrollments.expires_at>?3
                       AND admins.active=1",
                    params![admin_id, enrollment_token_hash, now],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, u64>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )
                .optional()?;
            let Some((username, enrollment_key_id, enrollment_ciphertext)) = enrollment else {
                return Ok((
                    AdminMfaEnrollmentActivationOutcome::NotFoundOrExpired,
                    Vec::new(),
                ));
            };
            let totp_secret = self.decrypt_enrollment_totp(
                &enrollment_token_hash,
                enrollment_key_id,
                &enrollment_ciphertext,
            )?;
            let (totp_key_id, totp_ciphertext) =
                self.encrypt_admin_totp(&username, totp_secret.expose_secret())?;
            transaction.execute(
                "UPDATE admins SET totp_key_id=?2,totp_ciphertext=?3,
                     totp_generation=totp_generation+1,totp_enabled=1 WHERE id=?1",
                params![admin_id, totp_key_id, totp_ciphertext],
            )?;
            transaction.execute(
                "INSERT INTO admin_totp_replay(admin_id,last_step) VALUES(?1,?2)
                 ON CONFLICT(admin_id) DO UPDATE SET last_step=excluded.last_step",
                params![admin_id, verified_totp_step as i64],
            )?;
            revoke_admin_auth_state(transaction, admin_id)?;
            Ok((
                AdminMfaEnrollmentActivationOutcome::Activated,
                vec![RequiredAuditEvent::new(
                    AuditAction::AccountMfaChanged,
                    Some(admin_id.to_string()),
                    None,
                )],
            ))
        })
    }

    #[cfg(test)]
    pub fn cleanup_expired_admin_mfa_enrollments(&self) -> rusqlite::Result<usize> {
        self.try_conn()?.execute(
            "DELETE FROM admin_mfa_enrollments WHERE expires_at<=?1",
            [Utc::now().to_rfc3339()],
        )
    }

    #[cfg(test)]
    pub fn reset_admin_password(&self, id: i64, password_hash: &str) -> rusqlite::Result<bool> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE admins SET password_hash=?2 WHERE id=?1",
            params![id, password_hash],
        )? == 1;
        if changed {
            revoke_admin_auth_state(&transaction, id)?;
        }
        transaction.commit()?;
        Ok(changed)
    }

    #[cfg(test)]
    pub fn reset_admin_password_and_audit(
        &self,
        id: i64,
        password_hash: &str,
        context: &AuditContext,
    ) -> rusqlite::Result<bool> {
        self.required_transaction(context, |transaction| {
            let changed = transaction.execute(
                "UPDATE admins SET password_hash=?2 WHERE id=?1",
                params![id, password_hash],
            )? == 1;
            if changed {
                revoke_admin_auth_state(transaction, id)?;
            }
            let events = changed
                .then(|| {
                    RequiredAuditEvent::new(
                        AuditAction::AdminPasswordReset,
                        Some(id.to_string()),
                        None,
                    )
                })
                .into_iter()
                .collect();
            Ok((changed, events))
        })
    }

    #[cfg(test)]
    pub(crate) fn reset_admin_password_and_audit_audited(
        &self,
        id: i64,
        password_hash: &str,
        context: &AuditContext,
    ) -> rusqlite::Result<Audited<bool>> {
        self.required_transaction_audited(context, |transaction| {
            let changed = transaction.execute(
                "UPDATE admins SET password_hash=?2 WHERE id=?1",
                params![id, password_hash],
            )? == 1;
            if changed {
                revoke_admin_auth_state(transaction, id)?;
            }
            let events = changed
                .then(|| {
                    RequiredAuditEvent::new(
                        AuditAction::AdminPasswordReset,
                        Some(id.to_string()),
                        None,
                    )
                })
                .into_iter()
                .collect();
            Ok((changed, events))
        })
    }

    pub(crate) fn reset_admin_password_and_audit_for_session(
        &self,
        proof: &MfaSessionProof,
        id: i64,
        password_hash: &str,
        context: &AuditContext,
    ) -> rusqlite::Result<SessionBound<Audited<bool>>> {
        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
            let changed = transaction.execute(
                "UPDATE admins SET password_hash=?2 WHERE id=?1",
                params![id, password_hash],
            )? == 1;
            if changed {
                revoke_admin_auth_state(transaction, id)?;
            }
            let events = changed
                .then(|| {
                    RequiredAuditEvent::new(
                        AuditAction::AdminPasswordReset,
                        Some(id.to_string()),
                        None,
                    )
                })
                .into_iter()
                .collect();
            Ok((changed, events))
        })
    }
    #[cfg(test)]
    pub fn reset_admin_totp(&self, id: i64, totp_secret: &str) -> rusqlite::Result<Option<String>> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let username = transaction
            .query_row("SELECT username FROM admins WHERE id=?1", [id], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
        if let Some(username) = username.as_deref() {
            let (totp_key_id, totp_ciphertext) = self.encrypt_admin_totp(username, totp_secret)?;
            transaction.execute(
                "UPDATE admins SET totp_key_id=?2,totp_ciphertext=?3,
                     totp_generation=totp_generation+1,totp_enabled=1 WHERE id=?1",
                params![id, totp_key_id, totp_ciphertext],
            )?;
            transaction.execute(
                "DELETE FROM admin_webauthn_credentials WHERE admin_id=?1",
                [id],
            )?;
            transaction.execute("DELETE FROM admin_totp_replay WHERE admin_id=?1", [id])?;
            revoke_admin_auth_state(&transaction, id)?;
        }
        transaction.commit()?;
        Ok(username)
    }

    #[cfg(test)]
    pub fn reset_admin_totp_and_audit(
        &self,
        id: i64,
        totp_secret: &str,
        context: &AuditContext,
    ) -> rusqlite::Result<Option<String>> {
        let username = self
            .try_conn()?
            .query_row("SELECT username FROM admins WHERE id=?1", [id], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
        let encrypted = username
            .as_deref()
            .map(|username| self.encrypt_admin_totp(username, totp_secret))
            .transpose()?;
        self.required_transaction(context, |transaction| {
            if let Some((totp_key_id, totp_ciphertext)) = encrypted.as_ref() {
                transaction.execute(
                    "UPDATE admins SET totp_key_id=?2,totp_ciphertext=?3,
                         totp_generation=totp_generation+1,totp_enabled=1 WHERE id=?1",
                    params![id, totp_key_id, totp_ciphertext],
                )?;
                transaction.execute(
                    "DELETE FROM admin_webauthn_credentials WHERE admin_id=?1",
                    [id],
                )?;
                transaction.execute("DELETE FROM admin_totp_replay WHERE admin_id=?1", [id])?;
                revoke_admin_auth_state(transaction, id)?;
            }
            let events = username
                .is_some()
                .then(|| {
                    RequiredAuditEvent::new(AuditAction::AdminTotpReset, Some(id.to_string()), None)
                })
                .into_iter()
                .collect();
            Ok((username, events))
        })
    }

    pub(crate) fn reset_admin_totp_and_audit_for_session(
        &self,
        proof: &MfaSessionProof,
        id: i64,
        totp_secret: &str,
        context: &AuditContext,
    ) -> rusqlite::Result<SessionBound<Audited<Option<String>>>> {
        let username = self
            .try_conn()?
            .query_row("SELECT username FROM admins WHERE id=?1", [id], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
        let encrypted = username
            .as_deref()
            .map(|username| self.encrypt_admin_totp(username, totp_secret))
            .transpose()?;
        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
            if let Some((totp_key_id, totp_ciphertext)) = encrypted.as_ref() {
                transaction.execute(
                    "UPDATE admins SET totp_key_id=?2,totp_ciphertext=?3,
                         totp_generation=totp_generation+1,totp_enabled=1 WHERE id=?1",
                    params![id, totp_key_id, totp_ciphertext],
                )?;
                transaction.execute(
                    "DELETE FROM admin_webauthn_credentials WHERE admin_id=?1",
                    [id],
                )?;
                transaction.execute("DELETE FROM admin_totp_replay WHERE admin_id=?1", [id])?;
                revoke_admin_auth_state(transaction, id)?;
            }
            let events = username
                .is_some()
                .then(|| {
                    RequiredAuditEvent::new(AuditAction::AdminTotpReset, Some(id.to_string()), None)
                })
                .into_iter()
                .collect();
            Ok((username, events))
        })
    }
}
