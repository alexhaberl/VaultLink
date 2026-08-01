use super::{
    insert_required_audits, trace_required_audits, AuditAction, AuditContext, Database,
    RequiredAuditEvent,
};
use chrono::Utc;
use rusqlite::{params, TransactionBehavior};

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

    pub fn replace_runtime_settings_and_audit(
        &self,
        settings: &[(&str, String)],
        admin: i64,
        context: &AuditContext,
        audit_detail: String,
    ) -> rusqlite::Result<()> {
        self.replace_runtime_settings_internal(settings, admin, Some((context, audit_detail)))
    }

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
