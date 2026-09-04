#[cfg(test)]
use super::{insert_required_audits, trace_required_audits};
use super::{
    AuditAction, AuditContext, CommitPublication, Database, MfaSessionProof, RequiredAuditEvent,
    SessionBound,
};
use chrono::Utc;
use rusqlite::params;
#[cfg(test)]
use rusqlite::TransactionBehavior;

impl Database {
    pub fn runtime_settings(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let c = self.try_conn()?;
        let mut statement = c.prepare("SELECT key,value FROM runtime_settings ORDER BY key")?;
        let settings = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect();
        settings
    }
    #[cfg(test)]
    pub fn replace_runtime_settings(
        &self,
        settings: &[(&str, String)],
        admin: i64,
    ) -> rusqlite::Result<()> {
        self.replace_runtime_settings_internal(settings, admin, None)
    }

    #[cfg(test)]
    pub fn replace_runtime_settings_and_audit(
        &self,
        settings: &[(&str, String)],
        admin: i64,
        context: &AuditContext,
        audit_detail: String,
    ) -> rusqlite::Result<()> {
        self.replace_runtime_settings_internal(settings, admin, Some((context, audit_detail)))
    }

    pub(crate) fn replace_runtime_settings_for_mfa_session<T>(
        &self,
        proof: &MfaSessionProof,
        settings: &[(&str, String)],
        context: &AuditContext,
        audit_detail: String,
        publish_snapshot: impl FnOnce() -> T,
    ) -> rusqlite::Result<SessionBound<T>>
    where
        T: CommitPublication,
    {
        let admin = proof.admin_id();
        self.required_transaction_for_mfa_session_with_commit(
            proof,
            context,
            |transaction| {
                transaction.execute("DELETE FROM runtime_settings", [])?;
                let updated_at = Utc::now().to_rfc3339();
                {
                    let mut statement = transaction.prepare(
                        "INSERT INTO runtime_settings(key,value,updated_by,updated_at)
                         VALUES(?1,?2,?3,?4)",
                    )?;
                    for (key, value) in settings {
                        statement.execute(params![*key, value.as_str(), admin, updated_at])?;
                    }
                }
                // Publish only after every fallible settings statement has
                // succeeded. Required-audit insertion still follows in the
                // canonical helper; if it or COMMIT fails, a guard returned here
                // can restore the old snapshot before the writer fence is released.
                let publication = publish_snapshot();
                Ok((
                    publication,
                    vec![RequiredAuditEvent::new(
                        AuditAction::SettingsUpdated,
                        None,
                        Some(audit_detail),
                    )],
                ))
            },
            |publication| publication.accept_commit(),
        )
    }

    #[cfg(test)]
    fn replace_runtime_settings_internal(
        &self,
        settings: &[(&str, String)],
        admin: i64,
        required_audit: Option<(&AuditContext, String)>,
    ) -> rusqlite::Result<()> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM runtime_settings", [])?;
        let updated_at = Utc::now().to_rfc3339();
        {
            let mut statement = transaction.prepare(
                "INSERT INTO runtime_settings(key,value,updated_by,updated_at)
                 VALUES(?1,?2,?3,?4)",
            )?;
            for (key, value) in settings {
                statement.execute(params![*key, value.as_str(), admin, updated_at])?;
            }
        }
        let (audit_context, audit_events) =
            required_audit.map_or((None, None), |(context, detail)| {
                (
                    Some(context),
                    Some([RequiredAuditEvent::new(
                        AuditAction::SettingsUpdated,
                        None,
                        Some(detail),
                    )]),
                )
            });
        if let (Some(context), Some(events)) = (audit_context, audit_events.as_ref()) {
            insert_required_audits(&transaction, context, events)?;
        }
        transaction.commit()?;
        if let (Some(context), Some(events)) = (audit_context, audit_events.as_ref()) {
            trace_required_audits(context, events);
        }
        Ok(())
    }
}
