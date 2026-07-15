use super::{
    insert_audit_event, token_hash, Admin, AdminDeactivationOutcome,
    AdminMfaEnrollmentActivationOutcome, AdminMfaEnrollmentStartOutcome,
    AdminPasswordChangeOutcome, AdminRecoveryOutcome, AdminSummary, AdminWebauthnCredential,
    AdminWebauthnCredentialDeletionOutcome, AdminWebauthnCredentialRegistrationOutcome, Database,
    InitialAdminOutcome, PasswordSessionCreationOutcome, PendingAdminMfaEnrollment, Session,
    ADMIN_MFA_ENROLLMENT_TTL_SECONDS,
};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

fn consume_admin_totp_step(
    transaction: &Transaction<'_>,
    admin_id: i64,
    step: u64,
) -> rusqlite::Result<bool> {
    if step > i64::MAX as u64 {
        return Ok(false);
    }
    let active = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM admins WHERE id=?1 AND active=1)",
        [admin_id],
        |row| row.get::<_, bool>(0),
    )?;
    if !active {
        return Ok(false);
    }
    Ok(transaction.execute(
        "INSERT INTO admin_totp_replay(admin_id,last_step) VALUES(?1,?2)
         ON CONFLICT(admin_id) DO UPDATE SET last_step=excluded.last_step
         WHERE excluded.last_step>admin_totp_replay.last_step",
        params![admin_id, step as i64],
    )? == 1)
}

fn cleanup_admin_mfa_enrollments(
    transaction: &Transaction<'_>,
    now: &str,
) -> rusqlite::Result<usize> {
    transaction.execute(
        "DELETE FROM admin_mfa_enrollments WHERE expires_at<=?1",
        [now],
    )
}

fn revoke_admin_auth_state(transaction: &Transaction<'_>, admin_id: i64) -> rusqlite::Result<()> {
    transaction.execute("DELETE FROM sessions WHERE admin_id=?1", [admin_id])?;
    transaction.execute(
        "DELETE FROM admin_mfa_enrollments WHERE admin_id=?1",
        [admin_id],
    )?;
    Ok(())
}

impl Database {
    pub fn create_initial_admin(
        &self,
        username: &str,
        password_hash: &str,
        totp_secret: &str,
    ) -> rusqlite::Result<InitialAdminOutcome> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let initialized: bool =
            transaction.query_row("SELECT EXISTS(SELECT 1 FROM admins)", [], |row| row.get(0))?;
        let outcome = if initialized {
            InitialAdminOutcome::AlreadyInitialized
        } else {
            transaction.execute(
                "INSERT INTO admins(username,password_hash,totp_secret,created_at,active) VALUES(?1,?2,?3,?4,1)",
                params![username, password_hash, totp_secret, Utc::now().to_rfc3339()],
            )?;
            InitialAdminOutcome::Created
        };
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn create_admin(
        &self,
        username: &str,
        password_hash: &str,
        totp_secret: &str,
    ) -> rusqlite::Result<()> {
        self.conn().execute(
            "INSERT INTO admins(username,password_hash,totp_secret,created_at,active) VALUES(?1,?2,?3,?4,1)",
            params![
                username,
                password_hash,
                totp_secret,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }
    pub fn admin(&self, username: &str) -> rusqlite::Result<Option<Admin>> {
        self.conn()
            .query_row(
                "SELECT id,username,password_hash,totp_secret,active FROM admins WHERE username=?1 AND active=1",
                [username],
                |r| {
                    Ok(Admin {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        password_hash: r.get(2)?,
                        totp_secret: r.get(3)?,
                        active: r.get::<_, i64>(4)? != 0,
                    })
                },
            )
            .optional()
    }
    pub fn admin_count(&self) -> rusqlite::Result<i64> {
        self.conn()
            .query_row("SELECT COUNT(*) FROM admins", [], |row| row.get(0))
    }
    pub fn active_admin_count(&self) -> rusqlite::Result<i64> {
        self.conn()
            .query_row("SELECT COUNT(*) FROM admins WHERE active=1", [], |row| {
                row.get(0)
            })
    }
    pub fn list_admins(&self) -> rusqlite::Result<Vec<AdminSummary>> {
        let c = self.conn();
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
    pub fn activate_admin(&self, id: i64) -> rusqlite::Result<bool> {
        Ok(self
            .conn()
            .execute("UPDATE admins SET active=1 WHERE id=?1", [id])?
            == 1)
    }

    pub fn deactivate_admin(&self, id: i64) -> rusqlite::Result<AdminDeactivationOutcome> {
        let mut connection = self.conn();
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
        transaction.commit()?;
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
        let mut connection = self.conn();
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
        transaction.execute(
            "UPDATE admins
             SET password_hash=COALESCE(?2,password_hash),
                 totp_secret=COALESCE(?3,totp_secret)
             WHERE id=?1",
            params![admin_id, password_hash, totp_secret],
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
        insert_audit_event(
            &transaction,
            "local_recovery",
            "admin_recovered",
            Some(&object_id),
            Some(&detail),
            None,
        )?;
        transaction.commit()?;
        tracing::warn!(
            target: "vaultlink::audit",
            actor = "local_recovery",
            action = "admin_recovered",
            object_id = object_id,
            username = canonical_username,
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
    pub fn change_admin_password_cas(
        &self,
        id: i64,
        expected_password_hash: &str,
        new_password_hash: &str,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<AdminPasswordChangeOutcome> {
        let mut connection = self.conn();
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
        insert_audit_event(
            &transaction,
            &username,
            "account_password_changed",
            Some(&object_id),
            None,
            client_ip,
        )?;
        transaction.commit()?;
        tracing::info!(target: "vaultlink::audit", actor = username, action = "account_password_changed", object_id, "audit event");
        Ok(AdminPasswordChangeOutcome::Changed)
    }

    /// Starts or replaces one short-lived enrollment. Only a hash of `token` is persisted.
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
        let mut connection = self.conn();
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
                 admin_id,token_hash,totp_secret,created_at,expires_at
             ) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(admin_id) DO UPDATE SET
                 token_hash=excluded.token_hash,
                 totp_secret=excluded.totp_secret,
                 created_at=excluded.created_at,
                 expires_at=excluded.expires_at",
            params![
                admin_id,
                enrollment_token_hash,
                totp_secret,
                now_string,
                expires_at
            ],
        )?;
        transaction.commit()?;
        Ok(AdminMfaEnrollmentStartOutcome::Started { expires_at })
    }

    /// Returns a pending secret only to a caller presenting the raw enrollment token.
    pub fn admin_mfa_enrollment(
        &self,
        admin_id: i64,
        token: &str,
    ) -> rusqlite::Result<Option<PendingAdminMfaEnrollment>> {
        let now = Utc::now().to_rfc3339();
        let enrollment_token_hash = token_hash(token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_admin_mfa_enrollments(&transaction, &now)?;
        let enrollment = transaction
            .query_row(
                "SELECT admin_mfa_enrollments.admin_id,
                        admin_mfa_enrollments.totp_secret,
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
                        totp_secret: row.get(1)?,
                        expires_at: row.get(2)?,
                    })
                },
            )
            .optional()?;
        transaction.commit()?;
        Ok(enrollment)
    }

    /// Activates and consumes an enrollment after the caller verified a code against its secret.
    /// The secret is never included in the audit event.
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
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        cleanup_admin_mfa_enrollments(&transaction, &now)?;
        let enrollment = transaction
            .query_row(
                "SELECT admins.username,admin_mfa_enrollments.totp_secret
                 FROM admin_mfa_enrollments
                 JOIN admins ON admins.id=admin_mfa_enrollments.admin_id
                 WHERE admin_mfa_enrollments.admin_id=?1
                   AND admin_mfa_enrollments.token_hash=?2
                   AND admin_mfa_enrollments.expires_at>?3
                   AND admins.active=1",
                params![admin_id, enrollment_token_hash, now],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((username, totp_secret)) = enrollment else {
            transaction.commit()?;
            return Ok(AdminMfaEnrollmentActivationOutcome::NotFoundOrExpired);
        };
        transaction.execute(
            "UPDATE admins SET totp_secret=?2 WHERE id=?1",
            params![admin_id, totp_secret],
        )?;
        transaction.execute(
            "INSERT INTO admin_totp_replay(admin_id,last_step) VALUES(?1,?2)
             ON CONFLICT(admin_id) DO UPDATE SET last_step=excluded.last_step",
            params![admin_id, verified_totp_step as i64],
        )?;
        revoke_admin_auth_state(&transaction, admin_id)?;
        let object_id = admin_id.to_string();
        insert_audit_event(
            &transaction,
            &username,
            "account_mfa_changed",
            Some(&object_id),
            None,
            client_ip,
        )?;
        transaction.commit()?;
        tracing::info!(target: "vaultlink::audit", actor = username, action = "account_mfa_changed", object_id, "audit event");
        Ok(AdminMfaEnrollmentActivationOutcome::Activated)
    }

    pub fn cleanup_expired_admin_mfa_enrollments(&self) -> rusqlite::Result<usize> {
        self.conn().execute(
            "DELETE FROM admin_mfa_enrollments WHERE expires_at<=?1",
            [Utc::now().to_rfc3339()],
        )
    }

    pub fn reset_admin_password(&self, id: i64, password_hash: &str) -> rusqlite::Result<bool> {
        let mut connection = self.conn();
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
    pub fn reset_admin_totp(&self, id: i64, totp_secret: &str) -> rusqlite::Result<Option<String>> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let username = transaction
            .query_row("SELECT username FROM admins WHERE id=?1", [id], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
        if username.is_some() {
            transaction.execute(
                "UPDATE admins SET totp_secret=?2 WHERE id=?1",
                params![id, totp_secret],
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
    pub fn admin_webauthn_credentials(
        &self,
        admin_id: i64,
    ) -> rusqlite::Result<Vec<AdminWebauthnCredential>> {
        let connection = self.conn();
        let mut statement = connection.prepare(
            "SELECT id,label,credential_id,credential_json,created_at,last_used_at
             FROM admin_webauthn_credentials WHERE admin_id=?1 ORDER BY id",
        )?;
        let rows = statement
            .query_map([admin_id], |row| {
                Ok(AdminWebauthnCredential {
                    id: row.get(0)?,
                    label: row.get(1)?,
                    credential_id: row.get(2)?,
                    credential_json: row.get(3)?,
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
        credential_json: &str,
    ) -> rusqlite::Result<i64> {
        let connection = self.conn();
        connection.execute(
            "INSERT INTO admin_webauthn_credentials(
                 admin_id,label,credential_id,credential_json,created_at
             ) VALUES(?1,?2,?3,?4,?5)",
            params![
                admin_id,
                label,
                credential_id,
                credential_json,
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
    #[allow(clippy::too_many_arguments)]
    pub fn add_admin_webauthn_credential_for_session(
        &self,
        session_token: &str,
        admin_id: i64,
        label: &str,
        credential_id: &str,
        credential_json: &str,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<AdminWebauthnCredentialRegistrationOutcome> {
        let now = Utc::now().to_rfc3339();
        let session_token_hash = token_hash(session_token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let username = transaction
            .query_row(
                "SELECT admins.username
                 FROM sessions
                 JOIN admins ON admins.id=sessions.admin_id
                 WHERE sessions.token_hash=?1
                   AND sessions.admin_id=?2
                   AND sessions.mfa_verified=1
                   AND sessions.expires_at>?3
                   AND admins.active=1",
                params![session_token_hash, admin_id, now],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(username) = username else {
            transaction.commit()?;
            return Ok(AdminWebauthnCredentialRegistrationOutcome::SessionUnavailable);
        };
        transaction.execute(
            "INSERT INTO admin_webauthn_credentials(
                 admin_id,label,credential_id,credential_json,created_at
             ) VALUES(?1,?2,?3,?4,?5)",
            params![admin_id, label, credential_id, credential_json, now],
        )?;
        let credential_row_id = transaction.last_insert_rowid();
        insert_audit_event(
            &transaction,
            &username,
            "webauthn_credential_added",
            None,
            None,
            client_ip,
        )?;
        transaction.commit()?;
        tracing::info!(target: "vaultlink::audit", actor = username, action = "webauthn_credential_added", "audit event");
        Ok(AdminWebauthnCredentialRegistrationOutcome::Registered(
            credential_row_id,
        ))
    }

    pub fn update_admin_webauthn_credential(
        &self,
        id: i64,
        admin_id: i64,
        credential_json: &str,
    ) -> rusqlite::Result<bool> {
        Ok(self.conn().execute(
            "UPDATE admin_webauthn_credentials
             SET credential_json=?3,last_used_at=?4
             WHERE id=?1 AND admin_id=?2",
            params![id, admin_id, credential_json, Utc::now().to_rfc3339()],
        )? == 1)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete_webauthn_mfa(
        &self,
        old_session_token: &str,
        new_session_token: &str,
        new_csrf_token: &str,
        credential_id: i64,
        admin_id: i64,
        expected_credential_json: &str,
        updated_credential_json: &str,
    ) -> rusqlite::Result<bool> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let credential_updated = transaction.execute(
            "UPDATE admin_webauthn_credentials
             SET credential_json=?5,last_used_at=?6
             WHERE id=?1 AND admin_id=?2 AND credential_json=?3
               AND EXISTS(
                   SELECT 1 FROM sessions
                   WHERE token_hash=?4 AND admin_id=?2 AND mfa_verified=0 AND expires_at>?6
               )",
            params![
                credential_id,
                admin_id,
                expected_credential_json,
                token_hash(old_session_token),
                updated_credential_json,
                Utc::now().to_rfc3339()
            ],
        )? == 1;
        if !credential_updated {
            transaction.rollback()?;
            return Ok(false);
        }
        let session_updated = transaction.execute(
            "UPDATE sessions
             SET token_hash=?4,csrf_token=?5,mfa_verified=1
             WHERE token_hash=?1 AND admin_id=?2 AND mfa_verified=0 AND expires_at>?3",
            params![
                token_hash(old_session_token),
                admin_id,
                Utc::now().to_rfc3339(),
                token_hash(new_session_token),
                new_csrf_token,
            ],
        )? == 1;
        if !session_updated {
            transaction.rollback()?;
            return Ok(false);
        }
        transaction.commit()?;
        Ok(true)
    }

    pub fn webauthn_credential_count(&self) -> rusqlite::Result<u64> {
        self.conn().query_row(
            "SELECT COUNT(*) FROM admin_webauthn_credentials",
            [],
            |row| row.get(0),
        )
    }

    pub fn delete_admin_webauthn_credential(
        &self,
        id: i64,
        admin_id: i64,
    ) -> rusqlite::Result<bool> {
        Ok(self.conn().execute(
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
    pub fn delete_admin_webauthn_credential_with_totp(
        &self,
        session_token: &str,
        id: i64,
        admin_id: i64,
        expected_password_hash: &str,
        expected_totp_secret: &str,
        totp_step: u64,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<AdminWebauthnCredentialDeletionOutcome> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let username = transaction
            .query_row(
                "SELECT admins.username
                 FROM sessions
                 JOIN admins ON admins.id=sessions.admin_id
                 WHERE sessions.token_hash=?1
                   AND sessions.admin_id=?2
                   AND sessions.mfa_verified=1
                   AND sessions.expires_at>?3
                   AND admins.active=1
                   AND admins.password_hash=?4
                   AND admins.totp_secret=?5",
                params![
                    token_hash(session_token),
                    admin_id,
                    Utc::now().to_rfc3339(),
                    expected_password_hash,
                    expected_totp_secret,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(username) = username else {
            transaction.rollback()?;
            return Ok(AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected);
        };
        if !consume_admin_totp_step(&transaction, admin_id, totp_step)? {
            transaction.commit()?;
            return Ok(AdminWebauthnCredentialDeletionOutcome::TotpRejected);
        }
        let deleted = transaction.execute(
            "DELETE FROM admin_webauthn_credentials
             WHERE id=?1 AND admin_id=?2
               AND (SELECT COUNT(*) FROM admin_webauthn_credentials WHERE admin_id=?2) <> 2",
            params![id, admin_id],
        )? == 1;
        if !deleted {
            transaction.rollback()?;
            return Ok(AdminWebauthnCredentialDeletionOutcome::NotDeleted);
        }
        let object_id = id.to_string();
        insert_audit_event(
            &transaction,
            &username,
            "webauthn_credential_deleted",
            Some(&object_id),
            None,
            client_ip,
        )?;
        transaction.commit()?;
        tracing::info!(target: "vaultlink::audit", actor = username, action = "webauthn_credential_deleted", object_id, "audit event");
        Ok(AdminWebauthnCredentialDeletionOutcome::Deleted)
    }
    pub fn create_session(
        &self,
        token: &str,
        admin_id: i64,
        csrf: &str,
        expires: DateTime<Utc>,
    ) -> rusqlite::Result<()> {
        let c = self.conn();
        c.execute(
            "DELETE FROM sessions WHERE expires_at < ?1",
            [Utc::now().to_rfc3339()],
        )?;
        c.execute(
            "INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at) VALUES(?1,?2,?3,?4)",
            params![token_hash(token), admin_id, csrf, expires.to_rfc3339()],
        )?;
        Ok(())
    }

    /// Creates a pre-MFA session only while the password hash verified by the caller is current.
    /// The active/hash predicate and insertion intentionally share one SQL statement.
    pub fn create_session_for_verified_password(
        &self,
        token: &str,
        admin_id: i64,
        expected_password_hash: &str,
        csrf: &str,
        expires: DateTime<Utc>,
    ) -> rusqlite::Result<PasswordSessionCreationOutcome> {
        let now = Utc::now().to_rfc3339();
        let session_token_hash = token_hash(token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM sessions WHERE expires_at < ?1", [&now])?;
        let created = transaction.execute(
            "INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at)
             SELECT ?1,admins.id,?4,?5
             FROM admins
             WHERE admins.id=?2 AND admins.password_hash=?3 AND admins.active=1",
            params![
                session_token_hash,
                admin_id,
                expected_password_hash,
                csrf,
                expires.to_rfc3339()
            ],
        )?;
        let outcome = if created == 1 {
            PasswordSessionCreationOutcome::Created
        } else {
            let admin = transaction
                .query_row(
                    "SELECT password_hash,active FROM admins WHERE id=?1",
                    [admin_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0)),
                )
                .optional()?;
            match admin {
                None => PasswordSessionCreationOutcome::AdminNotFound,
                Some((_, false)) => PasswordSessionCreationOutcome::AdminInactive,
                Some((password_hash, true)) if password_hash != expected_password_hash => {
                    PasswordSessionCreationOutcome::StalePassword
                }
                Some(_) => return Err(rusqlite::Error::InvalidQuery),
            }
        };
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn session(&self, token: &str) -> rusqlite::Result<Option<Session>> {
        self.conn().query_row("SELECT a.id,a.username,s.csrf_token,s.mfa_verified FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=?1 AND s.expires_at>?2 AND a.active=1",params![token_hash(token),Utc::now().to_rfc3339()],|r|Ok(Session{admin_id:r.get(0)?,username:r.get(1)?,csrf_token:r.get(2)?,mfa_verified:r.get::<_,i64>(3)?!=0})).optional()
    }
    /// Consumes a TOTP counter and verifies exactly the bound, unexpired session.
    /// Both writes share an IMMEDIATE transaction so one code cannot unlock two sessions.
    pub fn verify_mfa_with_totp_step(
        &self,
        old_token: &str,
        new_token: &str,
        new_csrf_token: &str,
        admin_id: i64,
        step: u64,
    ) -> rusqlite::Result<bool> {
        let now = Utc::now().to_rfc3339();
        let session_token_hash = token_hash(old_token);
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let valid_session = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sessions
                 JOIN admins ON admins.id=sessions.admin_id
                 WHERE sessions.token_hash=?1 AND sessions.admin_id=?2
                   AND sessions.expires_at>?3 AND sessions.mfa_verified=0
                   AND admins.active=1
             )",
            params![session_token_hash, admin_id, now],
            |row| row.get::<_, bool>(0),
        )?;
        if !valid_session || !consume_admin_totp_step(&transaction, admin_id, step)? {
            transaction.commit()?;
            return Ok(false);
        }
        let changed = transaction.execute(
            "UPDATE sessions
             SET token_hash=?4,csrf_token=?5,mfa_verified=1
             WHERE token_hash=?1 AND admin_id=?2 AND expires_at>?3 AND mfa_verified=0",
            params![
                session_token_hash,
                admin_id,
                now,
                token_hash(new_token),
                new_csrf_token,
            ],
        )?;
        if changed != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        transaction.commit()?;
        Ok(true)
    }

    /// Consumes one TOTP counter for a sensitive authenticated operation.
    pub fn consume_admin_totp_step(&self, admin_id: i64, step: u64) -> rusqlite::Result<bool> {
        let mut connection = self.conn();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let consumed = consume_admin_totp_step(&transaction, admin_id, step)?;
        transaction.commit()?;
        Ok(consumed)
    }

    #[cfg(test)]
    pub fn verify_mfa(&self, token: &str) -> rusqlite::Result<bool> {
        Ok(self.conn().execute(
            "UPDATE sessions SET mfa_verified=1 WHERE token_hash=?1 AND expires_at>?2",
            params![token_hash(token), Utc::now().to_rfc3339()],
        )? == 1)
    }
    pub fn delete_session(&self, token: &str) -> rusqlite::Result<()> {
        self.conn().execute(
            "DELETE FROM sessions WHERE token_hash=?1",
            [token_hash(token)],
        )?;
        Ok(())
    }
}
