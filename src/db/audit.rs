use super::{
    insert_required_audits, trace_required_audits, AuditAction, AuditClientIpDeletionOutcome,
    AuditContext, AuditEvent, AuditPriority, AuditRetentionOutcome, AuditSortColumn,
    AuditSortDirection, Database, RequiredAuditEvent, MAX_AUDIT_ROWS,
};
use chrono::Utc;
#[cfg(test)]
use rusqlite::Connection;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

#[cfg(test)]
pub(super) fn enforce_audit_retention(
    connection: &Connection,
    maximum_rows: i64,
) -> rusqlite::Result<usize> {
    if maximum_rows < 1 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut statement = connection.prepare(
        "DELETE FROM audit
         WHERE id IN (
             SELECT id FROM audit
             ORDER BY priority ASC,id ASC
             LIMIT MAX((SELECT COUNT(*) FROM audit) - ?1, 0)
         )
         RETURNING priority",
    )?;
    let priorities = statement
        .query_map([maximum_rows], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(priorities.len())
}

pub(super) fn insert_audit_event(
    transaction: &Transaction<'_>,
    action: AuditAction,
    actor: &str,
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
        "INSERT INTO audit(occurred_at,actor,action,object_id,detail,client_ip,priority)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            Utc::now().to_rfc3339(),
            actor,
            action.as_str(),
            object_id,
            detail,
            client_ip,
            action.priority().as_i64()
        ],
    )?;
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
    pub fn cleanup_audit_retention(&self) -> rusqlite::Result<AuditRetentionOutcome> {
        const BATCH_SIZE: i64 = 1_000;
        let mut outcome = AuditRetentionOutcome::default();
        loop {
            let mut connection = self.try_conn()?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let count: i64 =
                transaction.query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))?;
            let excess = count.saturating_sub(MAX_AUDIT_ROWS);
            if excess == 0 {
                transaction.commit()?;
                break;
            }
            let batch = excess.min(BATCH_SIZE);
            let priorities = {
                let mut statement = transaction.prepare(
                    "DELETE FROM audit WHERE id IN (
                     SELECT id FROM audit
                     ORDER BY priority ASC,id ASC
                     LIMIT ?1
                 )
                 RETURNING priority",
                )?;
                let priorities = statement
                    .query_map([batch], |row| row.get::<_, i64>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                priorities
            };
            transaction.commit()?;
            for priority in &priorities {
                if *priority >= AuditPriority::Security.as_i64() {
                    outcome.security_deleted = outcome.security_deleted.saturating_add(1);
                } else {
                    outcome.routine_deleted = outcome.routine_deleted.saturating_add(1);
                }
            }
            if priorities.is_empty() {
                break;
            }
        }
        Ok(outcome)
    }

    #[cfg(test)]
    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        object: Option<&str>,
        detail: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.audit_test_with_priority_and_client_ip(
            AuditPriority::Routine,
            actor,
            action,
            object,
            detail,
            None,
        )
    }

    pub(crate) fn audit_action_with_client_ip(
        &self,
        action: AuditAction,
        actor: &str,
        object: Option<&str>,
        detail: Option<&str>,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<()> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_audit_event(&transaction, action, actor, object, detail, client_ip)?;
        transaction.commit()?;
        drop(connection);
        // Client IP retention is SQLite-only. Never mirror it into tracing/journald.
        tracing::info!(target: "vaultlink::audit", actor, action = action.as_str(), object_id = object.unwrap_or(""), detail = detail.unwrap_or(""), "audit event");
        Ok(())
    }

    #[cfg(test)]
    fn audit_test_with_priority_and_client_ip(
        &self,
        priority: AuditPriority,
        actor: &str,
        action: &str,
        object: Option<&str>,
        detail: Option<&str>,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<()> {
        let mut connection = self.try_conn()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let client_ip = if persisted_audit_client_ip_enabled(&transaction, client_ip.is_some())? {
            client_ip
        } else {
            None
        };
        transaction.execute(
            "INSERT INTO audit(occurred_at,actor,action,object_id,detail,client_ip,priority)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                Utc::now().to_rfc3339(),
                actor,
                action,
                object,
                detail,
                client_ip,
                priority.as_i64()
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub fn audit_with_client_ip(
        &self,
        actor: &str,
        action: &str,
        object: Option<&str>,
        detail: Option<&str>,
        client_ip: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.audit_test_with_priority_and_client_ip(
            AuditPriority::Routine,
            actor,
            action,
            object,
            detail,
            client_ip,
        )
    }

    pub fn count_audit_client_ips(&self) -> rusqlite::Result<u64> {
        self.try_conn()?.query_row(
            "SELECT COUNT(*) FROM audit WHERE client_ip IS NOT NULL",
            [],
            |row| row.get(0),
        )
    }

    #[cfg(test)]
    pub fn audit_priorities(&self, action: &str) -> rusqlite::Result<Vec<i64>> {
        let connection = self.try_conn()?;
        let mut statement =
            connection.prepare("SELECT priority FROM audit WHERE action=?1 ORDER BY id")?;
        let priorities = statement
            .query_map([action], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(priorities)
    }

    #[cfg(test)]
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
            AuditAction::AuditClientIpsDeleted,
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
