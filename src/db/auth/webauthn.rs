impl Database {
    pub fn admin_webauthn_credentials(
        &self,
        admin_id: i64,
    ) -> rusqlite::Result<Vec<AdminWebauthnCredential>> {
        let connection = self.try_conn()?;
        let mut statement = connection.prepare(
            "SELECT id,label,credential_id,credential_blob,created_at,last_used_at
             FROM admin_webauthn_credentials WHERE admin_id=?1 ORDER BY id",
        )?;
        let rows = statement
            .query_map([admin_id], |row| {
                Ok(AdminWebauthnCredential {
                    id: row.get(0)?,
                    label: row.get(1)?,
                    credential_id: row.get(2)?,
                    credential_blob: row.get(3)?,
                    created_at: row.get(4)?,
                    last_used_at: row.get(5)?,
                })
            })?
            .collect();
        rows
    }

    #[cfg(test)]
    pub(super) fn add_admin_webauthn_credential(
        &self,
        admin_id: i64,
        label: &str,
        credential_id: &str,
        credential_blob: &(impl AsRef<[u8]> + ?Sized),
    ) -> rusqlite::Result<i64> {
        let connection = self.try_conn()?;
        connection.execute(
            "INSERT INTO admin_webauthn_credentials(
                 admin_id,label,credential_id,credential_blob,created_at
             ) VALUES(?1,?2,?3,?4,?5)",
            params![
                admin_id,
                label,
                credential_id,
                credential_blob.as_ref(),
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(connection.last_insert_rowid())
    }

    /// Persists a completed WebAuthn registration only if the session that
    /// authorized the ceremony is still active, unexpired and MFA-verified.
    /// The session predicate, credential insert and audit event share one
    /// transaction so an MFA reset either removes the new key afterwards or
    /// makes a stale completion fail before it can restore a credential.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn add_admin_webauthn_credential_for_session(
        &self,
        session_token: &str,
        admin_id: i64,
        label: &str,
        credential_id: &str,
        credential_blob: &(impl AsRef<[u8]> + ?Sized),
        client_ip: Option<&str>,
    ) -> rusqlite::Result<AdminWebauthnCredentialRegistrationOutcome> {
        let proof = MfaSessionProof::from_token(session_token, admin_id);
        Ok(
            match self.add_admin_webauthn_credential_for_mfa_session(
                &proof,
                label,
                credential_id,
                credential_blob,
                client_ip,
            )? {
                SessionBound::Authorized(outcome) => outcome.into_legacy_inner(),
                SessionBound::SessionUnavailable => {
                    AdminWebauthnCredentialRegistrationOutcome::SessionUnavailable
                }
            },
        )
    }

    /// Inserts a verified WebAuthn credential through an already-open live
    /// session transaction. Callers must use the transaction supplied by
    /// `required_transaction_for_mfa_session`; this helper never checks out a
    /// second connection.
    pub(crate) fn insert_admin_webauthn_credential_in_transaction(
        transaction: &Transaction<'_>,
        proof: &MfaSessionProof,
        label: &str,
        credential_id: &str,
        credential_blob: &(impl AsRef<[u8]> + ?Sized),
    ) -> rusqlite::Result<i64> {
        let created_at = Utc::now().to_rfc3339();
        transaction.execute(
            "INSERT INTO admin_webauthn_credentials(
                 admin_id,label,credential_id,credential_blob,created_at
             ) VALUES(?1,?2,?3,?4,?5)",
            params![
                proof.admin_id(),
                label,
                credential_id,
                credential_blob.as_ref(),
                created_at
            ],
        )?;
        Ok(transaction.last_insert_rowid())
    }

    #[cfg(test)]
    pub(crate) fn add_admin_webauthn_credential_for_mfa_session(
        &self,
        proof: &MfaSessionProof,
        label: &str,
        credential_id: &str,
        credential_blob: &(impl AsRef<[u8]> + ?Sized),
        client_ip: Option<&str>,
    ) -> rusqlite::Result<SessionBound<Audited<AdminWebauthnCredentialRegistrationOutcome>>> {
        let username = self
            .try_conn()?
            .query_row(
                "SELECT username FROM admins WHERE id=?1",
                [proof.admin_id()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_default();
        let audit_context = AuditContext::new(username, client_ip.map(str::to_string));
        self.required_transaction_for_mfa_session_audited(proof, &audit_context, |transaction| {
            let credential_row_id = Self::insert_admin_webauthn_credential_in_transaction(
                transaction,
                proof,
                label,
                credential_id,
                credential_blob,
            )?;
            Ok((
                AdminWebauthnCredentialRegistrationOutcome::Registered(credential_row_id),
                vec![RequiredAuditEvent::new(
                    AuditAction::WebauthnCredentialAdded,
                    None,
                    None,
                )],
            ))
        })
    }

    #[cfg(test)]
    pub fn update_admin_webauthn_credential(
        &self,
        id: i64,
        admin_id: i64,
        credential_blob: &(impl AsRef<[u8]> + ?Sized),
    ) -> rusqlite::Result<bool> {
        Ok(self.try_conn()?.execute(
            "UPDATE admin_webauthn_credentials
             SET credential_blob=?3,last_used_at=?4
             WHERE id=?1 AND admin_id=?2",
            params![
                id,
                admin_id,
                credential_blob.as_ref(),
                Utc::now().to_rfc3339()
            ],
        )? == 1)
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub fn complete_webauthn_mfa(
        &self,
        old_session_token: &str,
        new_session_token: &str,
        new_csrf_token: &str,
        credential_id: i64,
        admin_id: i64,
        expected_credential_blob: &[u8],
        updated_credential_blob: &[u8],
    ) -> rusqlite::Result<bool> {
        self.complete_webauthn_mfa_internal(
            old_session_token,
            new_session_token,
            new_csrf_token,
            credential_id,
            admin_id,
            expected_credential_blob,
            updated_credential_blob,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete_webauthn_mfa_and_audit(
        &self,
        old_session_token: &str,
        new_session_token: &str,
        new_csrf_token: &str,
        credential_id: i64,
        admin_id: i64,
        expected_credential_blob: &[u8],
        updated_credential_blob: &[u8],
        context: &AuditContext,
    ) -> rusqlite::Result<bool> {
        self.complete_webauthn_mfa_internal(
            old_session_token,
            new_session_token,
            new_csrf_token,
            credential_id,
            admin_id,
            expected_credential_blob,
            updated_credential_blob,
            Some(context),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn complete_webauthn_mfa_and_audit_audited(
        &self,
        old_session_token: &str,
        new_session_token: &str,
        new_csrf_token: &str,
        credential_id: i64,
        admin_id: i64,
        expected_credential_blob: &[u8],
        updated_credential_blob: &[u8],
        context: &AuditContext,
    ) -> rusqlite::Result<RequiredAuditDecision<(), ()>> {
        self.complete_webauthn_mfa_internal(
            old_session_token,
            new_session_token,
            new_csrf_token,
            credential_id,
            admin_id,
            expected_credential_blob,
            updated_credential_blob,
            Some(context),
        )
        .map(|completed| {
            if completed {
                RequiredAuditDecision::Committed(Audited::new(()))
            } else {
                RequiredAuditDecision::Rejected(())
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn complete_webauthn_mfa_internal(
        &self,
        old_session_token: &str,
        new_session_token: &str,
        new_csrf_token: &str,
        credential_id: i64,
        admin_id: i64,
        expected_credential_blob: &[u8],
        updated_credential_blob: &[u8],
        required_audit: Option<&AuditContext>,
    ) -> rusqlite::Result<bool> {
        let times = self.session_times(Utc::now());
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let credential_updated = transaction.execute(
            "UPDATE admin_webauthn_credentials
             SET credential_blob=?5,last_used_at=?6
             WHERE id=?1 AND admin_id=?2 AND credential_blob=?3
               AND EXISTS(
                   SELECT 1 FROM sessions
                   WHERE token_hash=?4 AND admin_id=?2 AND mfa_verified=0
                     AND expires_at>?6 AND last_activity_at>?7
               )",
            params![
                credential_id,
                admin_id,
                expected_credential_blob,
                token_hash(old_session_token),
                updated_credential_blob,
                times.now,
                times.idle_cutoff,
            ],
        )? == 1;
        if !credential_updated {
            transaction.rollback()?;
            return Ok(false);
        }
        let session_updated = transaction.execute(
            "UPDATE sessions
             SET token_hash=?4,csrf_token=?5,mfa_verified=1,last_activity_at=?3
             WHERE token_hash=?1 AND admin_id=?2 AND mfa_verified=0
               AND expires_at>?3 AND last_activity_at>?6",
            params![
                token_hash(old_session_token),
                admin_id,
                times.now,
                token_hash(new_session_token),
                new_csrf_token,
                times.idle_cutoff,
            ],
        )? == 1;
        if !session_updated {
            transaction.rollback()?;
            return Ok(false);
        }
        let audit_events = [RequiredAuditEvent::new(
            AuditAction::LoginSuccessWebauthn,
            None,
            None,
        )];
        if let Some(context) = required_audit {
            insert_required_audits(&transaction, context, &audit_events)?;
        }
        transaction.commit()?;
        if let Some(context) = required_audit {
            trace_required_audits(context, &audit_events);
        }
        Ok(true)
    }

    pub fn webauthn_credential_count(&self) -> rusqlite::Result<u64> {
        self.try_conn()?.query_row(
            "SELECT COUNT(*) FROM admin_webauthn_credentials",
            [],
            |row| row.get(0),
        )
    }

    #[cfg(test)]
    pub fn delete_admin_webauthn_credential(
        &self,
        id: i64,
        admin_id: i64,
    ) -> rusqlite::Result<bool> {
        Ok(self.try_conn()?.execute(
            "DELETE FROM admin_webauthn_credentials
             WHERE id=?1 AND admin_id=?2
               AND (SELECT COUNT(*) FROM admin_webauthn_credentials WHERE admin_id=?2) <> 2",
            params![id, admin_id],
        )? == 1)
    }

    /// Re-checks the exact live MFA session and credential snapshot, consumes
    /// the reauthentication TOTP step, applies the credential deletion policy
    /// and records the success audit as one serialized transaction. This closes
    /// both cancellation gaps and credential/session reset races.
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub fn delete_admin_webauthn_credential_with_totp(
        &self,
        session_token: &str,
        id: i64,
        admin_id: i64,
        expected_password_hash: &str,
        expected_totp_generation: u64,
        totp_step: u64,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<AdminWebauthnCredentialDeletionOutcome> {
        let proof = MfaSessionProof::from_token(session_token, admin_id);
        Ok(
            match self.delete_admin_webauthn_credential_with_totp_for_mfa_session(
                &proof,
                id,
                expected_password_hash,
                expected_totp_generation,
                totp_step,
                client_ip,
            )? {
                SessionBound::Authorized(outcome) => outcome.into_legacy_inner(),
                SessionBound::SessionUnavailable => {
                    AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected
                }
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn delete_admin_webauthn_credential_with_totp_for_mfa_session(
        &self,
        proof: &MfaSessionProof,
        id: i64,
        expected_password_hash: &str,
        expected_totp_generation: u64,
        totp_step: u64,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<SessionBound<Audited<AdminWebauthnCredentialDeletionOutcome>>> {
        let username = self
            .try_conn()?
            .query_row(
                "SELECT username FROM admins WHERE id=?1",
                [proof.admin_id()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_default();
        let audit_context = AuditContext::new(username, client_ip.map(str::to_string));
        self.required_transaction_for_mfa_session_audited(proof, &audit_context, |transaction| {
            let reauthentication_matches = transaction.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM admins
                     WHERE id=?1 AND active=1 AND password_hash=?2 AND totp_generation=?3
                 )",
                params![
                    proof.admin_id(),
                    expected_password_hash,
                    expected_totp_generation,
                ],
                |row| row.get::<_, bool>(0),
            )?;
            if !reauthentication_matches {
                return Ok((
                    AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected,
                    Vec::new(),
                ));
            }
            // Preserve the security error ordering of the original atomic
            // implementation: a replayed TOTP must not be masked by the
            // credential-count policy. This check does not consume a fresh
            // step, so a policy-rejected deletion can still be retried after
            // another key has been registered.
            if !admin_totp_step_is_fresh(transaction, proof.admin_id(), totp_step)? {
                return Ok((
                    AdminWebauthnCredentialDeletionOutcome::TotpRejected,
                    Vec::new(),
                ));
            }
            let deletable = transaction.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM admin_webauthn_credentials
                     WHERE id=?1 AND admin_id=?2
                       AND (SELECT COUNT(*) FROM admin_webauthn_credentials WHERE admin_id=?2) <> 2
                 )",
                params![id, proof.admin_id()],
                |row| row.get::<_, bool>(0),
            )?;
            if !deletable {
                return Ok((
                    AdminWebauthnCredentialDeletionOutcome::NotDeleted,
                    Vec::new(),
                ));
            }
            if !consume_admin_totp_step(transaction, proof.admin_id(), totp_step)? {
                return Ok((
                    AdminWebauthnCredentialDeletionOutcome::TotpRejected,
                    Vec::new(),
                ));
            }
            if transaction.execute(
                "DELETE FROM admin_webauthn_credentials WHERE id=?1 AND admin_id=?2",
                params![id, proof.admin_id()],
            )? != 1
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            revoke_admin_auth_state(transaction, proof.admin_id())?;
            Ok((
                AdminWebauthnCredentialDeletionOutcome::Deleted,
                vec![RequiredAuditEvent::new(
                    AuditAction::WebauthnCredentialDeleted,
                    Some(id.to_string()),
                    None,
                )],
            ))
        })
    }

    #[cfg(test)]
    pub fn delete_admin_webauthn_credential_without_totp(
        &self,
        session_token: &str,
        id: i64,
        admin_id: i64,
        expected_password_hash: &str,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<AdminWebauthnCredentialDeletionOutcome> {
        let proof = MfaSessionProof::from_token(session_token, admin_id);
        Ok(
            match self.delete_admin_webauthn_credential_without_totp_for_mfa_session(
                &proof,
                id,
                expected_password_hash,
                client_ip,
            )? {
                SessionBound::Authorized(outcome) => outcome.into_legacy_inner(),
                SessionBound::SessionUnavailable => {
                    AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected
                }
            },
        )
    }

    pub(crate) fn delete_admin_webauthn_credential_without_totp_for_mfa_session(
        &self,
        proof: &MfaSessionProof,
        id: i64,
        expected_password_hash: &str,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<SessionBound<Audited<AdminWebauthnCredentialDeletionOutcome>>> {
        let username = self
            .try_conn()?
            .query_row(
                "SELECT username FROM admins WHERE id=?1",
                [proof.admin_id()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_default();
        let audit_context = AuditContext::new(username, client_ip.map(str::to_string));
        self.required_transaction_for_mfa_session_audited(proof, &audit_context, |transaction| {
            let reauthentication_matches = transaction.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM admins
                     WHERE id=?1 AND active=1 AND password_hash=?2 AND totp_enabled=0
                 )",
                params![proof.admin_id(), expected_password_hash],
                |row| row.get::<_, bool>(0),
            )?;
            if !reauthentication_matches {
                return Ok((
                    AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected,
                    Vec::new(),
                ));
            }
            let deletable = transaction.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM admin_webauthn_credentials
                     WHERE id=?1 AND admin_id=?2
                       AND (SELECT COUNT(*) FROM admin_webauthn_credentials WHERE admin_id=?2) > 2
                 )",
                params![id, proof.admin_id()],
                |row| row.get::<_, bool>(0),
            )?;
            if !deletable {
                return Ok((
                    AdminWebauthnCredentialDeletionOutcome::NotDeleted,
                    Vec::new(),
                ));
            }
            if transaction.execute(
                "DELETE FROM admin_webauthn_credentials WHERE id=?1 AND admin_id=?2",
                params![id, proof.admin_id()],
            )? != 1
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            revoke_admin_auth_state(transaction, proof.admin_id())?;
            Ok((
                AdminWebauthnCredentialDeletionOutcome::Deleted,
                vec![RequiredAuditEvent::new(
                    AuditAction::WebauthnCredentialDeleted,
                    Some(id.to_string()),
                    Some("totp_disabled".into()),
                )],
            ))
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub fn set_admin_totp_enabled_with_reauthentication(
        &self,
        session_token: &str,
        admin_id: i64,
        expected_password_hash: &str,
        expected_totp_generation: u64,
        enabled: bool,
        totp_step: Option<u64>,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<AdminTotpSettingOutcome> {
        let proof = MfaSessionProof::from_token(session_token, admin_id);
        Ok(
            match self.set_admin_totp_enabled_with_reauthentication_for_mfa_session(
                &proof,
                expected_password_hash,
                expected_totp_generation,
                enabled,
                totp_step,
                client_ip,
            )? {
                SessionBound::Authorized(outcome) => outcome.into_legacy_inner(),
                SessionBound::SessionUnavailable => {
                    AdminTotpSettingOutcome::ReauthenticationRejected
                }
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn set_admin_totp_enabled_with_reauthentication_for_mfa_session(
        &self,
        proof: &MfaSessionProof,
        expected_password_hash: &str,
        expected_totp_generation: u64,
        enabled: bool,
        totp_step: Option<u64>,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<SessionBound<Audited<AdminTotpSettingOutcome>>> {
        let username = self
            .try_conn()?
            .query_row(
                "SELECT username FROM admins WHERE id=?1",
                [proof.admin_id()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_default();
        let audit_context = AuditContext::new(username, client_ip.map(str::to_string));
        self.required_transaction_for_mfa_session_audited(proof, &audit_context, |transaction| {
            let current = transaction
                .query_row(
                    "SELECT totp_enabled FROM admins
                     WHERE id=?1 AND active=1 AND password_hash=?2 AND totp_generation=?3",
                    params![
                        proof.admin_id(),
                        expected_password_hash,
                        expected_totp_generation,
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .optional()?;
            let Some(currently_enabled) = current else {
                return Ok((
                    AdminTotpSettingOutcome::ReauthenticationRejected,
                    Vec::new(),
                ));
            };
            if currently_enabled == enabled {
                return Ok((AdminTotpSettingOutcome::Unchanged, Vec::new()));
            }
            if !enabled {
                let key_count: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM admin_webauthn_credentials WHERE admin_id=?1",
                    [proof.admin_id()],
                    |row| row.get(0),
                )?;
                if key_count < 2 {
                    return Ok((
                        AdminTotpSettingOutcome::InsufficientSecurityKeys,
                        Vec::new(),
                    ));
                }
                let Some(step) = totp_step else {
                    return Ok((AdminTotpSettingOutcome::TotpRejected, Vec::new()));
                };
                if !consume_admin_totp_step(transaction, proof.admin_id(), step)? {
                    return Ok((AdminTotpSettingOutcome::TotpRejected, Vec::new()));
                }
            }
            if transaction.execute(
                "UPDATE admins SET totp_enabled=?2 WHERE id=?1 AND totp_enabled<>?2",
                params![proof.admin_id(), enabled],
            )? != 1
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok((
                AdminTotpSettingOutcome::Updated,
                vec![RequiredAuditEvent::new(
                    if enabled {
                        AuditAction::AdminTotpEnabled
                    } else {
                        AuditAction::AdminTotpDisabled
                    },
                    Some(proof.admin_id().to_string()),
                    None,
                )],
            ))
        })
    }
}
