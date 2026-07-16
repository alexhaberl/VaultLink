use super::{
    insert_required_audits, trace_required_audits, AuditClientIpDeletionOutcome, AuditContext,
    AuditEvent, AuditSortColumn, AuditSortDirection, Database, RequiredAuditEvent, MAX_AUDIT_ROWS,
};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

pub(super) fn enforce_audit_retention(
    connection: &Connection,
    maximum_rows: i64,
) -> rusqlite::Result<usize> {
    if maximum_rows < 1 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    connection.execute(
        "DELETE FROM audit
         WHERE id IN (
             SELECT id FROM audit
             ORDER BY id ASC
             LIMIT MAX((SELECT COUNT(*) FROM audit) - ?1, 0)
         )",
        [maximum_rows],
    )
}

pub(super) fn insert_audit_event(
    transaction: &Transaction<'_>,
    actor: &str,
    action: &str,
    object_id: Option<&str>,
    detail: Option<&str>,
    client_ip: Option<&str>,
) -> rusqlite::Result<()> {
    // Runtime settings and audit events live in the same database so privacy
    // decisions can be enforced at commit time. A request that captured an IP
    // before logging was disabled must not be able to write it afterwards.
    let client_ip = if persisted_audit_client_ip_enabled(transaction, client_ip.is_some())? {
        client_ip
    } else {
        None
    };
    transaction.execute(
        "INSERT INTO audit(occurred_at,actor,action,object_id,detail,client_ip)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            Utc::now().to_rfc3339(),
            actor,
            action,
            object_id,
            detail,
            client_ip
        ],
    )?;
    enforce_audit_retention(transaction, MAX_AUDIT_ROWS)?;
    Ok(())
}

fn persisted_audit_client_ip_enabled(
    transaction: &Transaction<'_>,
    fallback: bool,
) -> rusqlite::Result<bool> {
    let persisted = transaction
        .query_row(
            "SELECT value FROM runtime_settings WHERE key='audit_client_ip_enabled'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    Ok(match persisted.as_deref() {
        Some(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        ),
        None => fallback,
    })
}

impl Database {
    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        object: Option<&str>,
        detail: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.audit_with_client_ip(actor, action, object, detail, None)
    }

    pub fn audit_with_client_ip(
        &self,
        actor: &str,
        action: &str,
        object: Option<&str>,
        detail: Option<&str>,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<()> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_audit_event(&transaction, actor, action, object, detail, client_ip)?;
        transaction.commit()?;
        drop(connection);
        // Client IP retention is SQLite-only. Never mirror it into tracing/journald.
        tracing::info!(target: "vaultlink::audit", actor, action, object_id = object.unwrap_or(""), detail = detail.unwrap_or(""), "audit event");
        Ok(())
    }

    pub fn count_audit_client_ips(&self) -> rusqlite::Result<u64> {
        self.try_conn()?.query_row(
            "SELECT COUNT(*) FROM audit WHERE client_ip IS NOT NULL",
            [],
            |row| row.get(0),
        )
    }

    pub fn delete_audit_client_ips_if_disabled(
        &self,
        fallback_logging_enabled: bool,
    ) -> rusqlite::Result<AuditClientIpDeletionOutcome> {
        self.delete_audit_client_ips_if_disabled_internal(fallback_logging_enabled, None)
    }

    pub fn delete_audit_client_ips_if_disabled_and_audit(
        &self,
        fallback_logging_enabled: bool,
        context: &AuditContext,
    ) -> rusqlite::Result<AuditClientIpDeletionOutcome> {
        self.delete_audit_client_ips_if_disabled_internal(fallback_logging_enabled, Some(context))
    }

    fn delete_audit_client_ips_if_disabled_internal(
        &self,
        fallback_logging_enabled: bool,
        required_audit: Option<&AuditContext>,
    ) -> rusqlite::Result<AuditClientIpDeletionOutcome> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if persisted_audit_client_ip_enabled(&transaction, fallback_logging_enabled)? {
            return Ok(AuditClientIpDeletionOutcome::LoggingEnabled);
        }
        let deleted = transaction.execute(
            "UPDATE audit SET client_ip=NULL WHERE client_ip IS NOT NULL",
            [],
        )?;
        let audit_events = [RequiredAuditEvent::new(
            "audit_client_ips_deleted",
            None,
            Some(format!("deleted={deleted}")),
        )];
        if let Some(context) = required_audit {
            insert_required_audits(&transaction, context, &audit_events)?;
        }
        transaction.commit()?;
        if let Some(context) = required_audit {
            trace_required_audits(context, &audit_events);
        }
        Ok(AuditClientIpDeletionOutcome::Deleted(deleted))
    }

    pub fn list_audit(
        &self,
        action: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> rusqlite::Result<Vec<AuditEvent>> {
        self.list_audit_sorted(
            action,
            limit,
            offset,
            AuditSortColumn::Time,
            AuditSortDirection::Descending,
        )
    }

    pub fn list_audit_sorted(
        &self,
        action: Option<&str>,
        limit: usize,
        offset: usize,
        column: AuditSortColumn,
        direction: AuditSortDirection,
    ) -> rusqlite::Result<Vec<AuditEvent>> {
        let connection = self.try_conn()?;
        let column = match column {
            AuditSortColumn::Time => "occurred_at",
            AuditSortColumn::Actor => "actor COLLATE NOCASE",
            AuditSortColumn::Action => "action COLLATE NOCASE",
            AuditSortColumn::Object => "COALESCE(object_id, '') COLLATE NOCASE",
            AuditSortColumn::Detail => "COALESCE(detail, '') COLLATE NOCASE",
            AuditSortColumn::ClientIp => "COALESCE(client_ip, '') COLLATE NOCASE",
        };
        let direction = match direction {
            AuditSortDirection::Ascending => "ASC",
            AuditSortDirection::Descending => "DESC",
        };
        if let Some(action) = action {
            let query = format!(
                "SELECT occurred_at,actor,action,object_id,detail,client_ip
                 FROM audit WHERE action=?1
                 ORDER BY {column} {direction},id {direction}
                 LIMIT ?2 OFFSET ?3"
            );
            let mut statement = connection.prepare(&query)?;
            let events = statement
                .query_map(params![action, limit as i64, offset as i64], |row| {
                    Ok(AuditEvent {
                        occurred_at: row.get(0)?,
                        actor: row.get(1)?,
                        action: row.get(2)?,
                        object_id: row.get(3)?,
                        detail: row.get(4)?,
                        client_ip: row.get(5)?,
                    })
                })?
                .collect();
            events
        } else {
            let query = format!(
                "SELECT occurred_at,actor,action,object_id,detail,client_ip
                 FROM audit
                 ORDER BY {column} {direction},id {direction}
                 LIMIT ?1 OFFSET ?2"
            );
            let mut statement = connection.prepare(&query)?;
            let events = statement
                .query_map(params![limit as i64, offset as i64], |row| {
                    Ok(AuditEvent {
                        occurred_at: row.get(0)?,
                        actor: row.get(1)?,
                        action: row.get(2)?,
                        object_id: row.get(3)?,
                        detail: row.get(4)?,
                        client_ip: row.get(5)?,
                    })
                })?
                .collect();
            events
        }
    }

    pub fn count_audit(&self, action: Option<&str>) -> rusqlite::Result<usize> {
        let connection = self.try_conn()?;
        let count: i64 = if let Some(action) = action {
            connection.query_row(
                "SELECT COUNT(*) FROM audit WHERE action=?1",
                params![action],
                |row| row.get(0),
            )?
        } else {
            connection.query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))?
        };
        Ok(count.max(0) as usize)
    }
}
