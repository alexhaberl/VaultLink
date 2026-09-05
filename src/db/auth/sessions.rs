impl Database {
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

    /// Loads and touches the session and, only after the database has verified
    /// MFA, binds it to the opaque proof used at the later commit boundary.
    pub(crate) fn authenticated_mfa_session(
        &self,
        token: &str,
    ) -> rusqlite::Result<Option<MfaSessionAuthentication>> {
        let Some(session) = self.session(token)? else {
            return Ok(None);
        };
        if !session.mfa_verified {
            return Ok(Some(MfaSessionAuthentication::MfaRequired));
        }
        Ok(Some(MfaSessionAuthentication::Authenticated(
            MfaMutationContext::new(token, session),
        )))
    }

    fn session_at(&self, token: &str, now: DateTime<Utc>) -> rusqlite::Result<Option<Session>> {
        let times = self.session_times(now);
        let session_token_hash = token_hash(token);
        let connection = self.try_conn()?;
        let session_and_touch = connection
            .query_row(
                "SELECT a.id,a.username,s.csrf_token,s.mfa_verified,
                        s.last_activity_at<=?4
                 FROM sessions s
                 JOIN admins a ON a.id=s.admin_id
                 WHERE s.token_hash=?1 AND s.expires_at>?2
                   AND s.last_activity_at>?3 AND a.active=1",
                params![
                    session_token_hash,
                    times.now,
                    times.idle_cutoff,
                    times.touch_cutoff,
                ],
                |row| {
                    Ok((
                        Session {
                            admin_id: row.get(0)?,
                            username: row.get(1)?,
                            csrf_token: row.get(2)?,
                            mfa_verified: row.get::<_, i64>(3)? != 0,
                        },
                        row.get::<_, i64>(4)? != 0,
                    ))
                },
            )
            .optional()?;
        match session_and_touch {
            Some((session, touch_due)) => {
                if touch_due {
                    // Keep the predicates on the write: another reader may
                    // already have touched, expired or revoked this session
                    // after the SELECT and before this guarded UPDATE.
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
                }
                Ok(Some(session))
            }
            None => {
                connection.execute(
                    "DELETE FROM sessions WHERE token_hash=?1
                       AND (expires_at<=?2 OR last_activity_at<=?3)",
                    params![session_token_hash, times.now, times.idle_cutoff],
                )?;
                Ok(None)
            }
        }
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

    /// Executes one audited database mutation only if the exact MFA session is
    /// still live after this connection has acquired SQLite's writer slot.
    ///
    /// The session predicate, mutation and required audit events share one
    /// `BEGIN IMMEDIATE` transaction. Session revocation therefore either wins
    /// before the predicate (and the closure is never called), or waits until
    /// the complete authorized mutation has committed.
    ///
    /// Callers must acquire application-level mutation locks before entering
    /// this method. The closure must use the supplied transaction instead of
    /// checking out another database connection, which keeps lock ordering
    /// deterministic and avoids pool/SQLite lock inversion.
    #[cfg(test)]
    pub(crate) fn required_transaction_for_mfa_session<T, E, F>(
        &self,
        proof: &MfaSessionProof,
        context: &AuditContext,
        operation: F,
    ) -> Result<SessionBound<T>, E>
    where
        E: From<rusqlite::Error>,
        F: FnOnce(&Transaction<'_>) -> Result<(T, Vec<RequiredAuditEvent>), E>,
    {
        self.required_transaction_for_mfa_session_audited(proof, context, operation)
            .map(|outcome| outcome.map(Audited::into_legacy_inner))
    }

    pub(crate) fn required_transaction_for_mfa_session_audited<T, E, F>(
        &self,
        proof: &MfaSessionProof,
        context: &AuditContext,
        operation: F,
    ) -> Result<SessionBound<Audited<T>>, E>
    where
        E: From<rusqlite::Error>,
        F: FnOnce(&Transaction<'_>) -> Result<(T, Vec<RequiredAuditEvent>), E>,
    {
        self.required_transaction_for_mfa_session_with_commit_audited(
            proof,
            context,
            operation,
            |_| {},
        )
    }

    /// Variant for a transaction-coupled in-memory publication. `committed`
    /// must only disarm the publication's rollback guard; the visible snapshot
    /// itself is installed by `operation` while the writer transaction is
    /// still open. It is invoked immediately after a successful COMMIT and
    /// before tracing or any other post-commit work can unwind.
    #[cfg(test)]
    pub(crate) fn required_transaction_for_mfa_session_with_commit<T, E, F, C>(
        &self,
        proof: &MfaSessionProof,
        context: &AuditContext,
        operation: F,
        committed: C,
    ) -> Result<SessionBound<T>, E>
    where
        E: From<rusqlite::Error>,
        F: FnOnce(&Transaction<'_>) -> Result<(T, Vec<RequiredAuditEvent>), E>,
        C: FnOnce(&mut T),
    {
        self.required_transaction_for_mfa_session_with_commit_audited(
            proof, context, operation, committed,
        )
        .map(|outcome| outcome.map(Audited::into_legacy_inner))
    }

    pub(crate) fn required_transaction_for_mfa_session_with_commit_audited<T, E, F, C>(
        &self,
        proof: &MfaSessionProof,
        context: &AuditContext,
        operation: F,
        committed: C,
    ) -> Result<SessionBound<Audited<T>>, E>
    where
        E: From<rusqlite::Error>,
        F: FnOnce(&Transaction<'_>) -> Result<(T, Vec<RequiredAuditEvent>), E>,
        C: FnOnce(&mut T),
    {
        let mut connection = self.try_conn()?;
        let mut transaction =
            connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let times = self.session_times(Utc::now());
        if !live_mfa_session(&transaction, proof, &times)? {
            transaction.rollback()?;
            return Ok(SessionBound::SessionUnavailable);
        }
        context.validate()?;
        let (outcome, events) = operation(&transaction)?;
        insert_required_audits(&transaction, context, &events)?;
        // Commit without consuming `transaction`.  If COMMIT fails, drop the
        // operation outcome first: snapshot-publication outcomes use `Drop`
        // to restore their previous in-memory value while SQLite's writer
        // fence is still held.  Only then may the transaction roll back and a
        // waiting revocation proceed.
        if let Err(error) = transaction.execute_batch("COMMIT") {
            drop(outcome);
            drop(events);
            let _ = transaction.rollback();
            return Err(error.into());
        }
        let mut outcome = outcome;
        committed(&mut outcome);
        transaction.set_drop_behavior(DropBehavior::Ignore);
        drop(transaction);
        trace_required_audits(context, &events);
        Ok(SessionBound::Authorized(Audited::new(outcome)))
    }

    /// Holds SQLite's writer slot from the exact-session check through one
    /// non-database commit, such as publishing a staged upload.
    ///
    /// This transaction is intentionally rollback-only: it exists as a
    /// cross-connection and cross-process authorization fence and makes no
    /// database changes of its own. As above, callers acquire any application
    /// mutation lock before entering the fence and the closure must not perform
    /// nested database work.
    pub(crate) fn with_live_mfa_fence<T, E>(
        &self,
        proof: &MfaSessionProof,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<SessionBound<T>, E>
    where
        E: From<rusqlite::Error>,
    {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let times = self.session_times(Utc::now());
        if !live_mfa_session(&transaction, proof, &times)? {
            transaction.rollback()?;
            return Ok(SessionBound::SessionUnavailable);
        }
        let outcome = operation()?;
        // Dropping the read-only IMMEDIATE transaction releases the writer
        // fence without creating a misleading durable database mutation.
        drop(transaction);
        Ok(SessionBound::Authorized(outcome))
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

    pub(crate) fn delete_session_and_audit_audited(
        &self,
        token: &str,
        context: &AuditContext,
    ) -> rusqlite::Result<Audited<()>> {
        self.required_transaction_audited(context, |transaction| {
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
