#[cfg(test)]
use super::AdminMfaEnrollmentStartOutcome;
use super::{
    insert_required_audits, token_hash, trace_required_audits, Admin, AdminDeactivationOutcome,
    AdminMfaEnrollmentActivationOutcome, AdminPasswordChangeOutcome, AdminRecoveryOutcome,
    AdminSummary, AdminTotpSettingOutcome, AdminWebauthnCredential,
    AdminWebauthnCredentialDeletionOutcome, AdminWebauthnCredentialRegistrationOutcome,
    AuditAction, AuditContext, AuditedAdminMfaEnrollmentStartOutcome, Database,
    InitialAdminOutcome, PasswordSessionCreationOutcome, PendingAdminMfaEnrollment,
    RequiredAuditEvent, Session, ADMIN_MFA_ENROLLMENT_TTL_SECONDS,
};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

use crate::sensitive::SecretString;

const SESSION_TOUCH_INTERVAL_SECONDS: i64 = 60;

struct SessionTimes {
    now: String,
    idle_cutoff: String,
    touch_cutoff: String,
}

impl Database {
    fn session_times(&self, now: DateTime<Utc>) -> SessionTimes {
        SessionTimes {
            now: now.to_rfc3339(),
            idle_cutoff: (now - Duration::minutes(self.session_idle_minutes())).to_rfc3339(),
            touch_cutoff: (now - Duration::seconds(SESSION_TOUCH_INTERVAL_SECONDS)).to_rfc3339(),
        }
    }
}

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
    fn encrypt_admin_totp(
        &self,
        username: &str,
        totp_secret: &str,
    ) -> rusqlite::Result<(u64, Vec<u8>)> {
        self.encrypt_secret(
            totp_secret.as_bytes(),
            format!("admins.totp:{}", username.to_lowercase()).as_bytes(),
        )
    }

    fn decrypt_admin_totp(
        &self,
        username: &str,
        key_id: u64,
        ciphertext: &[u8],
    ) -> rusqlite::Result<SecretString> {
        let plaintext = self.decrypt_secret(
            key_id,
            ciphertext,
            format!("admins.totp:{}", username.to_lowercase()).as_bytes(),
        )?;
        String::from_utf8(plaintext)
            .map(SecretString::from)
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })
    }

    fn encrypt_enrollment_totp(
        &self,
        enrollment_token_hash: &str,
        totp_secret: &str,
    ) -> rusqlite::Result<(u64, Vec<u8>)> {
        self.encrypt_secret(
            totp_secret.as_bytes(),
            format!("admin_mfa_enrollments.totp:{enrollment_token_hash}").as_bytes(),
        )
    }

    fn decrypt_enrollment_totp(
        &self,
        enrollment_token_hash: &str,
        key_id: u64,
        ciphertext: &[u8],
    ) -> rusqlite::Result<SecretString> {
        let plaintext = self.decrypt_secret(
            key_id,
            ciphertext,
            format!("admin_mfa_enrollments.totp:{enrollment_token_hash}").as_bytes(),
        )?;
        String::from_utf8(plaintext)
            .map(SecretString::from)
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })
    }

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
        let mut statement =
            connection.prepare("SELECT username FROM admins WHERE active=1 ORDER BY id ASC")?;
        let usernames = statement
            .query_map([], |row| {
                row.get::<_, String>(0)
                    .map(|username| username.to_ascii_lowercase())
            })?
            .collect();
        usernames
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

    #[cfg(test)]
    pub fn deactivate_admin(&self, id: i64) -> rusqlite::Result<AdminDeactivationOutcome> {
        self.deactivate_admin_internal(id, None)
    }

    pub fn deactivate_admin_and_audit(
        &self,
        id: i64,
        context: &AuditContext,
    ) -> rusqlite::Result<AdminDeactivationOutcome> {
        self.deactivate_admin_internal(id, Some(context))
    }

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
        let times = self.session_times(Utc::now());
        let session_token_hash = token_hash(session_token);
        let mut connection = self.try_conn()?;
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
                   AND sessions.last_activity_at>?4
                   AND admins.active=1",
                params![session_token_hash, admin_id, times.now, times.idle_cutoff,],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(username) = username else {
            transaction.commit()?;
            return Ok(AdminWebauthnCredentialRegistrationOutcome::SessionUnavailable);
        };
        transaction.execute(
            "INSERT INTO admin_webauthn_credentials(
                 admin_id,label,credential_id,credential_blob,created_at
             ) VALUES(?1,?2,?3,?4,?5)",
            params![
                admin_id,
                label,
                credential_id,
                credential_blob.as_ref(),
                times.now
            ],
        )?;
        let credential_row_id = transaction.last_insert_rowid();
        let audit_context = AuditContext::new(&username, client_ip.map(str::to_string));
        let audit_events = [RequiredAuditEvent::new(
            AuditAction::WebauthnCredentialAdded,
            None,
            None,
        )];
        insert_required_audits(&transaction, &audit_context, &audit_events)?;
        transaction.commit()?;
        trace_required_audits(&audit_context, &audit_events);
        Ok(AdminWebauthnCredentialRegistrationOutcome::Registered(
            credential_row_id,
        ))
    }

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
        let times = self.session_times(Utc::now());
        let mut connection = self.try_conn()?;
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
                   AND sessions.last_activity_at>?4
                   AND admins.active=1
                   AND admins.password_hash=?5
                   AND admins.totp_generation=?6",
                params![
                    token_hash(session_token),
                    admin_id,
                    times.now,
                    times.idle_cutoff,
                    expected_password_hash,
                    expected_totp_generation,
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
        revoke_admin_auth_state(&transaction, admin_id)?;
        let object_id = id.to_string();
        let audit_context = AuditContext::new(&username, client_ip.map(str::to_string));
        let audit_events = [RequiredAuditEvent::new(
            AuditAction::WebauthnCredentialDeleted,
            Some(object_id),
            None,
        )];
        insert_required_audits(&transaction, &audit_context, &audit_events)?;
        transaction.commit()?;
        trace_required_audits(&audit_context, &audit_events);
        Ok(AdminWebauthnCredentialDeletionOutcome::Deleted)
    }

    pub fn delete_admin_webauthn_credential_without_totp(
        &self,
        session_token: &str,
        id: i64,
        admin_id: i64,
        expected_password_hash: &str,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<AdminWebauthnCredentialDeletionOutcome> {
        let times = self.session_times(Utc::now());
        let mut connection = self.try_conn()?;
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
                   AND sessions.last_activity_at>?4
                   AND admins.active=1
                   AND admins.password_hash=?5
                   AND admins.totp_enabled=0",
                params![
                    token_hash(session_token),
                    admin_id,
                    times.now,
                    times.idle_cutoff,
                    expected_password_hash,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(username) = username else {
            transaction.rollback()?;
            return Ok(AdminWebauthnCredentialDeletionOutcome::ReauthenticationRejected);
        };
        let deleted = transaction.execute(
            "DELETE FROM admin_webauthn_credentials
             WHERE id=?1 AND admin_id=?2
               AND (SELECT COUNT(*) FROM admin_webauthn_credentials WHERE admin_id=?2) > 2",
            params![id, admin_id],
        )? == 1;
        if !deleted {
            transaction.rollback()?;
            return Ok(AdminWebauthnCredentialDeletionOutcome::NotDeleted);
        }
        revoke_admin_auth_state(&transaction, admin_id)?;
        let object_id = id.to_string();
        let audit_context = AuditContext::new(&username, client_ip.map(str::to_string));
        let audit_events = [RequiredAuditEvent::new(
            AuditAction::WebauthnCredentialDeleted,
            Some(object_id),
            Some("totp_disabled".into()),
        )];
        insert_required_audits(&transaction, &audit_context, &audit_events)?;
        transaction.commit()?;
        trace_required_audits(&audit_context, &audit_events);
        Ok(AdminWebauthnCredentialDeletionOutcome::Deleted)
    }

    #[allow(clippy::too_many_arguments)]
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
        let times = self.session_times(Utc::now());
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = transaction
            .query_row(
                "SELECT admins.username,admins.totp_enabled
                 FROM sessions
                 JOIN admins ON admins.id=sessions.admin_id
                 WHERE sessions.token_hash=?1
                   AND sessions.admin_id=?2
                   AND sessions.mfa_verified=1
                   AND sessions.expires_at>?3
                   AND sessions.last_activity_at>?4
                   AND admins.active=1
                   AND admins.password_hash=?5
                   AND admins.totp_generation=?6",
                params![
                    token_hash(session_token),
                    admin_id,
                    times.now,
                    times.idle_cutoff,
                    expected_password_hash,
                    expected_totp_generation,
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?;
        let Some((username, currently_enabled)) = current else {
            transaction.rollback()?;
            return Ok(AdminTotpSettingOutcome::ReauthenticationRejected);
        };
        if currently_enabled == enabled {
            transaction.rollback()?;
            return Ok(AdminTotpSettingOutcome::Unchanged);
        }
        if !enabled {
            let key_count: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM admin_webauthn_credentials WHERE admin_id=?1",
                [admin_id],
                |row| row.get(0),
            )?;
            if key_count < 2 {
                transaction.rollback()?;
                return Ok(AdminTotpSettingOutcome::InsufficientSecurityKeys);
            }
            let Some(step) = totp_step else {
                transaction.rollback()?;
                return Ok(AdminTotpSettingOutcome::TotpRejected);
            };
            if !consume_admin_totp_step(&transaction, admin_id, step)? {
                transaction.commit()?;
                return Ok(AdminTotpSettingOutcome::TotpRejected);
            }
        }
        let changed = transaction.execute(
            "UPDATE admins SET totp_enabled=?2 WHERE id=?1 AND totp_enabled<>?2",
            params![admin_id, enabled],
        )?;
        if changed != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let action = if enabled {
            AuditAction::AdminTotpEnabled
        } else {
            AuditAction::AdminTotpDisabled
        };
        let audit_context = AuditContext::new(&username, client_ip.map(str::to_string));
        let audit_events = [RequiredAuditEvent::new(
            action,
            Some(admin_id.to_string()),
            None,
        )];
        insert_required_audits(&transaction, &audit_context, &audit_events)?;
        transaction.commit()?;
        trace_required_audits(&audit_context, &audit_events);
        Ok(AdminTotpSettingOutcome::Updated)
    }
    #[cfg(test)]
    pub fn create_session(
        &self,
        token: &str,
        admin_id: i64,
        csrf: &str,
        expires: DateTime<Utc>,
    ) -> rusqlite::Result<()> {
        let times = self.session_times(Utc::now());
        let c = self.try_conn()?;
        c.execute(
            "DELETE FROM sessions WHERE expires_at<=?1 OR last_activity_at<=?2",
            params![times.now, times.idle_cutoff],
        )?;
        c.execute(
            "INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at,last_activity_at)
             VALUES(?1,?2,?3,?4,?5)",
            params![
                token_hash(token),
                admin_id,
                csrf,
                expires.to_rfc3339(),
                times.now
            ],
        )?;
        Ok(())
    }

    /// Creates a pre-MFA session only while the password hash verified by the caller is current.
    /// The active/hash predicate and insertion intentionally share one SQL statement.
    #[cfg(test)]
    pub fn create_session_for_verified_password(
        &self,
        token: &str,
        admin_id: i64,
        expected_password_hash: &str,
        csrf: &str,
        expires: DateTime<Utc>,
    ) -> rusqlite::Result<PasswordSessionCreationOutcome> {
        self.create_session_for_verified_password_internal(
            token,
            admin_id,
            expected_password_hash,
            csrf,
            expires,
            None,
        )
    }

    pub fn create_session_for_verified_password_and_audit(
        &self,
        token: &str,
        admin_id: i64,
        expected_password_hash: &str,
        csrf: &str,
        expires: DateTime<Utc>,
        context: &AuditContext,
    ) -> rusqlite::Result<PasswordSessionCreationOutcome> {
        self.create_session_for_verified_password_internal(
            token,
            admin_id,
            expected_password_hash,
            csrf,
            expires,
            Some(context),
        )
    }

    fn create_session_for_verified_password_internal(
        &self,
        token: &str,
        admin_id: i64,
        expected_password_hash: &str,
        csrf: &str,
        expires: DateTime<Utc>,
        required_audit: Option<&AuditContext>,
    ) -> rusqlite::Result<PasswordSessionCreationOutcome> {
        let times = self.session_times(Utc::now());
        let session_token_hash = token_hash(token);
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM sessions WHERE expires_at<=?1 OR last_activity_at<=?2",
            params![times.now, times.idle_cutoff],
        )?;
        let created = transaction.execute(
            "INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at,last_activity_at)
             SELECT ?1,admins.id,?4,?5,?6
             FROM admins
             WHERE admins.id=?2 AND admins.password_hash=?3 AND admins.active=1",
            params![
                session_token_hash,
                admin_id,
                expected_password_hash,
                csrf,
                expires.to_rfc3339(),
                times.now,
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
        let audit_events = (outcome == PasswordSessionCreationOutcome::Created)
            .then(|| RequiredAuditEvent::new(AuditAction::PasswordVerified, None, None))
            .into_iter()
            .collect::<Vec<_>>();
        if let Some(context) = required_audit {
            insert_required_audits(&transaction, context, &audit_events)?;
        }
        transaction.commit()?;
        if let Some(context) = required_audit {
            trace_required_audits(context, &audit_events);
        }
        Ok(outcome)
    }

    pub fn session(&self, token: &str) -> rusqlite::Result<Option<Session>> {
        self.session_at(token, Utc::now())
    }

    fn session_at(&self, token: &str, now: DateTime<Utc>) -> rusqlite::Result<Option<Session>> {
        let times = self.session_times(now);
        let session_token_hash = token_hash(token);
        let connection = self.try_conn()?;
        let session = connection
            .query_row(
                "SELECT a.id,a.username,s.csrf_token,s.mfa_verified
                 FROM sessions s
                 JOIN admins a ON a.id=s.admin_id
                 WHERE s.token_hash=?1 AND s.expires_at>?2
                   AND s.last_activity_at>?3 AND a.active=1",
                params![session_token_hash, times.now, times.idle_cutoff],
                |row| {
                    Ok(Session {
                        admin_id: row.get(0)?,
                        username: row.get(1)?,
                        csrf_token: row.get(2)?,
                        mfa_verified: row.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .optional()?;
        if session.is_some() {
            connection.execute(
                "UPDATE sessions SET last_activity_at=?2
                 WHERE token_hash=?1 AND last_activity_at<=?3
                   AND expires_at>?2 AND last_activity_at>?4",
                params![
                    session_token_hash,
                    times.now,
                    times.touch_cutoff,
                    times.idle_cutoff,
                ],
            )?;
        } else {
            connection.execute(
                "DELETE FROM sessions WHERE token_hash=?1
                   AND (expires_at<=?2 OR last_activity_at<=?3)",
                params![session_token_hash, times.now, times.idle_cutoff],
            )?;
        }
        Ok(session)
    }

    #[cfg(test)]
    pub(crate) fn session_at_for_test(
        &self,
        token: &str,
        now: DateTime<Utc>,
    ) -> rusqlite::Result<Option<Session>> {
        self.session_at(token, now)
    }

    #[cfg(test)]
    pub(crate) fn expire_session_for_test(&self, token: &str) -> rusqlite::Result<()> {
        self.try_conn()?.execute(
            "UPDATE sessions SET expires_at=?2 WHERE token_hash=?1",
            params![
                token_hash(token),
                (Utc::now() - Duration::seconds(1)).to_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// Runs `operation` only while the exact MFA session is still authorized.
    ///
    /// The database connection mutex remains held until `operation` returns. Callers
    /// can therefore linearize a non-database security-sensitive commit with logout,
    /// credential reset and administrator deactivation, all of which use the same
    /// connection mutex.
    pub fn with_live_mfa_session<T>(
        &self,
        token: &str,
        admin_id: i64,
        operation: impl FnOnce() -> T,
    ) -> rusqlite::Result<Option<T>> {
        let times = self.session_times(Utc::now());
        let connection = self.try_conn()?;
        let live = connection.query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM sessions
                 JOIN admins ON admins.id=sessions.admin_id
                 WHERE sessions.token_hash=?1
                   AND sessions.admin_id=?2
                   AND sessions.mfa_verified=1
                   AND sessions.expires_at>?3
                   AND sessions.last_activity_at>?4
                   AND admins.active=1
             )",
            params![token_hash(token), admin_id, times.now, times.idle_cutoff,],
            |row| row.get::<_, bool>(0),
        )?;
        if !live {
            return Ok(None);
        }
        let outcome = operation();
        drop(connection);
        Ok(Some(outcome))
    }

    /// Consumes a TOTP counter and verifies exactly the bound, unexpired session.
    /// Both writes share an IMMEDIATE transaction so one code cannot unlock two sessions.
    #[cfg(test)]
    pub fn verify_mfa_with_totp_step(
        &self,
        old_token: &str,
        new_token: &str,
        new_csrf_token: &str,
        admin_id: i64,
        step: u64,
    ) -> rusqlite::Result<bool> {
        self.verify_mfa_with_totp_step_internal(
            old_token,
            new_token,
            new_csrf_token,
            admin_id,
            step,
            None,
        )
    }

    pub fn verify_mfa_with_totp_step_and_audit(
        &self,
        old_token: &str,
        new_token: &str,
        new_csrf_token: &str,
        admin_id: i64,
        step: u64,
        context: &AuditContext,
    ) -> rusqlite::Result<bool> {
        self.verify_mfa_with_totp_step_internal(
            old_token,
            new_token,
            new_csrf_token,
            admin_id,
            step,
            Some(context),
        )
    }

    fn verify_mfa_with_totp_step_internal(
        &self,
        old_token: &str,
        new_token: &str,
        new_csrf_token: &str,
        admin_id: i64,
        step: u64,
        required_audit: Option<&AuditContext>,
    ) -> rusqlite::Result<bool> {
        let times = self.session_times(Utc::now());
        let session_token_hash = token_hash(old_token);
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let valid_session = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sessions
                 JOIN admins ON admins.id=sessions.admin_id
                 WHERE sessions.token_hash=?1 AND sessions.admin_id=?2
                   AND sessions.expires_at>?3 AND sessions.mfa_verified=0
                   AND sessions.last_activity_at>?4
                   AND admins.active=1 AND admins.totp_enabled=1
             )",
            params![session_token_hash, admin_id, times.now, times.idle_cutoff,],
            |row| row.get::<_, bool>(0),
        )?;
        if !valid_session || !consume_admin_totp_step(&transaction, admin_id, step)? {
            transaction.commit()?;
            return Ok(false);
        }
        let changed = transaction.execute(
            "UPDATE sessions
             SET token_hash=?4,csrf_token=?5,mfa_verified=1,last_activity_at=?3
             WHERE token_hash=?1 AND admin_id=?2 AND expires_at>?3
               AND last_activity_at>?6 AND mfa_verified=0",
            params![
                session_token_hash,
                admin_id,
                times.now,
                token_hash(new_token),
                new_csrf_token,
                times.idle_cutoff,
            ],
        )?;
        if changed != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let audit_events = [RequiredAuditEvent::new(
            AuditAction::LoginSuccess,
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

    /// Consumes one TOTP counter for a sensitive authenticated operation.
    #[cfg(test)]
    pub fn consume_admin_totp_step(&self, admin_id: i64, step: u64) -> rusqlite::Result<bool> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let consumed = consume_admin_totp_step(&transaction, admin_id, step)?;
        transaction.commit()?;
        Ok(consumed)
    }

    #[cfg(test)]
    pub fn verify_mfa(&self, token: &str) -> rusqlite::Result<bool> {
        let times = self.session_times(Utc::now());
        Ok(self.try_conn()?.execute(
            "UPDATE sessions SET mfa_verified=1,last_activity_at=?2
             WHERE token_hash=?1 AND expires_at>?2 AND last_activity_at>?3",
            params![token_hash(token), times.now, times.idle_cutoff],
        )? == 1)
    }
    #[cfg(test)]
    pub fn delete_session(&self, token: &str) -> rusqlite::Result<()> {
        self.try_conn()?.execute(
            "DELETE FROM sessions WHERE token_hash=?1",
            [token_hash(token)],
        )?;
        Ok(())
    }

    pub fn delete_session_and_audit(
        &self,
        token: &str,
        context: &AuditContext,
    ) -> rusqlite::Result<()> {
        self.required_transaction(context, |transaction| {
            transaction.execute(
                "DELETE FROM sessions WHERE token_hash=?1",
                [token_hash(token)],
            )?;
            Ok((
                (),
                vec![RequiredAuditEvent::new(AuditAction::Logout, None, None)],
            ))
        })
    }
}
