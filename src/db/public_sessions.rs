use super::{
    insert_required_audits, token_hash, trace_required_audits, AuditAction, AuditContext, Audited,
    Database, PreviewSessionCreateOutcome, RequiredAuditEvent, MAX_ACTIVE_PREVIEW_SESSIONS_GLOBAL,
    MAX_ACTIVE_PREVIEW_SESSIONS_PER_OWNER_SHARE, MAX_ACTIVE_PREVIEW_SESSIONS_PER_RESOURCE,
    MAX_ACTIVE_PREVIEW_SESSIONS_PER_SHARE,
};
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

impl Database {
    /// Creates an unlock session only while the exact share policy verified by
    /// the caller is still current. Password hashing happens outside SQLite, so
    /// the hash and epoch predicates close the reset/policy-change race between
    /// verification and session creation.
    #[cfg(test)]
    pub fn create_unlock_session_for_verified_password(
        &self,
        token: &str,
        share_id: i64,
        expected_password_hash: &str,
        expected_upload_policy_epoch: i64,
        csrf_token: &str,
        expires: DateTime<Utc>,
    ) -> rusqlite::Result<bool> {
        self.create_unlock_session_for_verified_password_internal(
            token,
            share_id,
            expected_password_hash,
            expected_upload_policy_epoch,
            csrf_token,
            expires,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_unlock_session_for_verified_password_and_audit(
        &self,
        token: &str,
        share_id: i64,
        expected_password_hash: &str,
        expected_upload_policy_epoch: i64,
        csrf_token: &str,
        expires: DateTime<Utc>,
        context: &AuditContext,
    ) -> rusqlite::Result<bool> {
        self.create_unlock_session_for_verified_password_internal(
            token,
            share_id,
            expected_password_hash,
            expected_upload_policy_epoch,
            csrf_token,
            expires,
            Some(context),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_unlock_session_for_verified_password_and_audit_audited(
        &self,
        token: &str,
        share_id: i64,
        expected_password_hash: &str,
        expected_upload_policy_epoch: i64,
        csrf_token: &str,
        expires: DateTime<Utc>,
        context: &AuditContext,
    ) -> rusqlite::Result<Audited<bool>> {
        self.create_unlock_session_for_verified_password_internal(
            token,
            share_id,
            expected_password_hash,
            expected_upload_policy_epoch,
            csrf_token,
            expires,
            Some(context),
        )
        .map(Audited::new)
    }

    #[allow(clippy::too_many_arguments)]
    fn create_unlock_session_for_verified_password_internal(
        &self,
        token: &str,
        share_id: i64,
        expected_password_hash: &str,
        expected_upload_policy_epoch: i64,
        csrf_token: &str,
        expires: DateTime<Utc>,
        required_audit: Option<&AuditContext>,
    ) -> rusqlite::Result<bool> {
        let now = Utc::now().to_rfc3339();
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM public_unlock_sessions WHERE expires_at<=?1",
            [&now],
        )?;
        let created = transaction.execute(
            "INSERT INTO public_unlock_sessions(token_hash,share_id,csrf_token,expires_at)
             SELECT ?1,shares.id,?5,?6
             FROM shares
             WHERE shares.id=?2
               AND shares.password_hash=?3
               AND shares.upload_policy_epoch=?4
               AND shares.active=1
               AND (shares.expires_at IS NULL OR shares.expires_at>?7)",
            params![
                token_hash(token),
                share_id,
                expected_password_hash,
                expected_upload_policy_epoch,
                csrf_token,
                expires.to_rfc3339(),
                now,
            ],
        )? == 1;
        let audit_events = created
            .then(|| {
                RequiredAuditEvent::new(
                    AuditAction::ShareUnlocked,
                    Some(share_id.to_string()),
                    None,
                )
            })
            .into_iter()
            .collect::<Vec<_>>();
        if let Some(context) = required_audit {
            insert_required_audits(&transaction, context, &audit_events)?;
        }
        transaction.commit()?;
        if let Some(context) = required_audit {
            trace_required_audits(context, &audit_events);
        }
        Ok(created)
    }
    pub fn unlock_session(&self, token: &str, share_id: i64) -> rusqlite::Result<bool> {
        self.try_conn()?.query_row("SELECT EXISTS(SELECT 1 FROM public_unlock_sessions WHERE token_hash=?1 AND share_id=?2 AND expires_at>?3)", params![token_hash(token), share_id, Utc::now().to_rfc3339()], |row| row.get(0))
    }
    pub fn unlock_session_csrf(
        &self,
        token: &str,
        share_id: i64,
    ) -> rusqlite::Result<Option<String>> {
        self.try_conn()?
            .query_row(
                "SELECT csrf_token FROM public_unlock_sessions
                 WHERE token_hash=?1 AND share_id=?2 AND expires_at>?3
                   AND csrf_token<>''",
                params![token_hash(token), share_id, Utc::now().to_rfc3339()],
                |row| row.get(0),
            )
            .optional()
    }
    pub fn create_preview_session(
        &self,
        token: &str,
        owner_key: &str,
        share_id: i64,
        relative_path: &str,
        expires: DateTime<Utc>,
    ) -> rusqlite::Result<PreviewSessionCreateOutcome> {
        let now = Utc::now().to_rfc3339();
        let owner_key_hash = token_hash(owner_key);
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM public_preview_sessions WHERE expires_at<=?1",
            [&now],
        )?;
        let bucket_rows: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM public_preview_sessions
             WHERE share_id=?1 AND relative_path=?2 AND owner_key_hash=?3",
            params![share_id, relative_path, owner_key_hash],
            |row| row.get(0),
        )?;
        let bucket_evictions = bucket_rows
            .saturating_sub(MAX_ACTIVE_PREVIEW_SESSIONS_PER_RESOURCE - 1)
            .max(0);
        let owner_rows: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM public_preview_sessions
             WHERE share_id=?1 AND owner_key_hash=?2",
            params![share_id, owner_key_hash],
            |row| row.get(0),
        )?;
        if owner_rows - bucket_evictions + 1 > MAX_ACTIVE_PREVIEW_SESSIONS_PER_OWNER_SHARE {
            transaction.commit()?;
            return Ok(PreviewSessionCreateOutcome::OwnerCapacityReached);
        }
        let share_rows: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM public_preview_sessions WHERE share_id=?1",
            [share_id],
            |row| row.get(0),
        )?;
        if share_rows - bucket_evictions + 1 > MAX_ACTIVE_PREVIEW_SESSIONS_PER_SHARE {
            transaction.commit()?;
            return Ok(PreviewSessionCreateOutcome::ShareCapacityReached);
        }
        let global_rows: i64 =
            transaction.query_row("SELECT COUNT(*) FROM public_preview_sessions", [], |row| {
                row.get(0)
            })?;
        if global_rows - bucket_evictions + 1 > MAX_ACTIVE_PREVIEW_SESSIONS_GLOBAL {
            transaction.commit()?;
            return Ok(PreviewSessionCreateOutcome::GlobalCapacityReached);
        }
        transaction.execute(
            "DELETE FROM public_preview_sessions
             WHERE share_id=?1 AND relative_path=?2 AND owner_key_hash=?3
               AND token_hash NOT IN (
                   SELECT token_hash FROM public_preview_sessions
                   WHERE share_id=?1 AND relative_path=?2
                     AND owner_key_hash=?3 AND expires_at>?4
                   ORDER BY expires_at DESC, token_hash DESC
                   LIMIT ?5
               )",
            params![
                share_id,
                relative_path,
                owner_key_hash,
                now,
                MAX_ACTIVE_PREVIEW_SESSIONS_PER_RESOURCE - 1
            ],
        )?;
        transaction.execute(
            "INSERT INTO public_preview_sessions(
                 token_hash,share_id,relative_path,expires_at,owner_key_hash
             ) VALUES(?1,?2,?3,?4,?5)",
            params![
                token_hash(token),
                share_id,
                relative_path,
                expires.to_rfc3339(),
                owner_key_hash
            ],
        )?;
        transaction.commit()?;
        Ok(PreviewSessionCreateOutcome::Created)
    }
    pub fn preview_session(
        &self,
        token: &str,
        share_id: i64,
        relative_path: &str,
    ) -> rusqlite::Result<bool> {
        self.try_conn()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM public_preview_sessions WHERE token_hash=?1 AND share_id=?2 AND relative_path=?3 AND expires_at>?4)",
            params![token_hash(token), share_id, relative_path, Utc::now().to_rfc3339()],
            |row| row.get(0),
        )
    }
}
