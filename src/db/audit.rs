#[cfg(test)]
use super::{insert_required_audits, trace_required_audits};
use super::{
    AuditAction, AuditClientIpDeletionOutcome, AuditContext, AuditCursor, AuditEvent,
    AuditKeysetPosition, AuditPriority, AuditRetentionOutcome, AuditSortColumn, AuditSortDirection,
    Audited, Database, MfaSessionProof, RequiredAuditEvent, SessionBound, MAX_AUDIT_ROWS,
};
use chrono::Utc;
#[cfg(test)]
use rusqlite::Connection;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

use crate::log_safety::EscapedLogValue;

pub(super) fn validate_audit_fields(
    actor: &str,
    action: &str,
    object: Option<&str>,
    detail: Option<&str>,
    client_ip: Option<&str>,
) -> rusqlite::Result<()> {
    if actor.len() > 64
        || action.len() > 64
        || object.is_some_and(|v| v.len() > 4096)
        || detail.is_some_and(|v| v.len() > 16384)
        || client_ip.is_some_and(|v| v.len() > 45 || v.parse::<std::net::IpAddr>().is_err())
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

const AUDIT_SELECT: &str = "SELECT id,occurred_at,CASE WHEN length(CAST(actor AS BLOB))>64 THEN '<oversized:' || length(CAST(actor AS BLOB)) || ' bytes>' ELSE actor END,CASE WHEN length(CAST(action AS BLOB))>64 THEN '<oversized:' || length(CAST(action AS BLOB)) || ' bytes>' ELSE action END,CASE WHEN length(CAST(object_id AS BLOB))>4096 THEN '<oversized:' || length(CAST(object_id AS BLOB)) || ' bytes>' ELSE object_id END,CASE WHEN length(CAST(detail AS BLOB))>16384 THEN '<oversized:' || length(CAST(detail AS BLOB)) || ' bytes>' ELSE detail END,CASE WHEN length(CAST(client_ip AS BLOB))>45 THEN '<oversized:' || length(CAST(client_ip AS BLOB)) || ' bytes>' ELSE client_ip END";

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
    validate_audit_fields(actor, action.as_str(), object_id, detail, client_ip)?;
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
        // The process-wide instance lock permits only one server for this
        // database, and this admission guard serializes calls on its clones.
        // It is therefore safe to count once while releasing SQLite's writer
        // slot between batches so normal request writes can make progress.
        let _retention_guard = self.audit_retention_guard()?;
        let mut outcome = AuditRetentionOutcome::default();
        let count: i64 = self
            .try_conn()?
            .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))?;
        // `count` is signed because SQLite returns INTEGER. A signed
        // saturating subtraction can still be negative below the cap,
        // and SQLite treats a negative LIMIT as unlimited.
        let mut remaining = count.saturating_sub(MAX_AUDIT_ROWS).max(0);
        while remaining > 0 {
            let batch = remaining.min(BATCH_SIZE);
            let mut connection = self.try_conn()?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let (deleted, routine_deleted, security_deleted) = {
                let mut statement = transaction.prepare(
                    "DELETE FROM audit WHERE id IN (
                     SELECT id FROM audit
                     ORDER BY priority ASC,id ASC
                     LIMIT ?1
                 )
                 RETURNING priority",
                )?;
                let mut rows = statement.query([batch])?;
                let mut deleted = 0_i64;
                let mut routine_deleted = 0_usize;
                let mut security_deleted = 0_usize;
                while let Some(row) = rows.next()? {
                    let priority = row.get::<_, i64>(0)?;
                    if priority >= AuditPriority::Security.as_i64() {
                        security_deleted = security_deleted.saturating_add(1);
                    } else {
                        routine_deleted = routine_deleted.saturating_add(1);
                    }
                    deleted = deleted.saturating_add(1);
                }
                (deleted, routine_deleted, security_deleted)
            };
            transaction.commit()?;
            if deleted == 0 {
                break;
            }
            outcome.routine_deleted = outcome.routine_deleted.saturating_add(routine_deleted);
            outcome.security_deleted = outcome.security_deleted.saturating_add(security_deleted);
            remaining = remaining.saturating_sub(deleted);
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
        tracing::info!(
            target: "vaultlink::audit",
            actor = %EscapedLogValue::new(actor),
            action = action.as_str(),
            object_id = %EscapedLogValue::new(object.unwrap_or("")),
            detail = %EscapedLogValue::new(detail.unwrap_or("")),
            "audit event"
        );
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

    #[cfg(test)]
    pub fn delete_audit_client_ips_if_disabled_and_audit(
        &self,
        fallback_logging_enabled: bool,
        context: &AuditContext,
    ) -> rusqlite::Result<AuditClientIpDeletionOutcome> {
        self.delete_audit_client_ips_if_disabled_internal(fallback_logging_enabled, Some(context))
    }

    pub(crate) fn delete_audit_client_ips_for_mfa_session(
        &self,
        proof: &MfaSessionProof,
        fallback_logging_enabled: bool,
        context: &AuditContext,
    ) -> rusqlite::Result<SessionBound<Audited<AuditClientIpDeletionOutcome>>> {
        self.required_transaction_for_mfa_session_audited(proof, context, |transaction| {
            if persisted_audit_client_ip_enabled(transaction, fallback_logging_enabled)? {
                return Ok((AuditClientIpDeletionOutcome::LoggingEnabled, Vec::new()));
            }
            let deleted = transaction.execute(
                "UPDATE audit SET client_ip=NULL WHERE client_ip IS NOT NULL",
                [],
            )?;
            Ok((
                AuditClientIpDeletionOutcome::Deleted(deleted),
                vec![RequiredAuditEvent::new(
                    AuditAction::AuditClientIpsDeleted,
                    None,
                    Some(format!("deleted={deleted}")),
                )],
            ))
        })
    }

    #[cfg(test)]
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
        let column = audit_sort_expression(column);
        let direction = audit_sort_direction_sql(direction);
        if let Some(action) = action {
            let query = format!(
                "{AUDIT_SELECT}
                 FROM audit WHERE action=?1
                 ORDER BY {column} {direction},id {direction}
                 LIMIT ?2 OFFSET ?3"
            );
            let mut statement = connection.prepare(&query)?;
            let events = statement
                .query_map(
                    params![action, limit as i64, offset as i64],
                    map_audit_event,
                )?
                .collect();
            events
        } else {
            let query = format!(
                "{AUDIT_SELECT}
                 FROM audit
                 ORDER BY {column} {direction},id {direction}
                 LIMIT ?1 OFFSET ?2"
            );
            let mut statement = connection.prepare(&query)?;
            let events = statement
                .query_map(params![limit as i64, offset as i64], map_audit_event)?
                .collect();
            events
        }
    }

    pub(crate) fn audit_cursor_exists(&self, id: i64) -> rusqlite::Result<bool> {
        self.try_conn()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM audit WHERE id=?1)",
            [id],
            |row| row.get(0),
        )
    }

    pub fn list_audit_keyset(
        &self,
        action: Option<&str>,
        limit: usize,
        column: AuditSortColumn,
        direction: AuditSortDirection,
        cursor: Option<&AuditCursor>,
        position: AuditKeysetPosition,
    ) -> rusqlite::Result<Vec<AuditEvent>> {
        let connection = self.try_conn()?;
        let column = audit_sort_expression(column);
        let displayed_direction = audit_sort_direction_sql(direction);
        let query_direction = if position == AuditKeysetPosition::Before {
            reverse_audit_sort_direction_sql(direction)
        } else {
            displayed_direction
        };
        let comparison = match (direction, position) {
            (AuditSortDirection::Ascending, AuditKeysetPosition::After)
            | (AuditSortDirection::Descending, AuditKeysetPosition::Before) => ">",
            (AuditSortDirection::Descending, AuditKeysetPosition::After)
            | (AuditSortDirection::Ascending, AuditKeysetPosition::Before) => "<",
        };
        let limit = limit.clamp(1, 1_000) as i64;
        let mut events = match (action, cursor) {
            (Some(action), Some(cursor)) => {
                let query = format!(
                    "{AUDIT_SELECT}
                     FROM audit
                     WHERE action=?1
                       AND ({column} {comparison} COALESCE(?2,(SELECT {column} FROM audit WHERE id=?3))
                            OR ({column} = COALESCE(?2,(SELECT {column} FROM audit WHERE id=?3)) AND id {comparison} ?3))
                     ORDER BY {column} {query_direction},id {query_direction}
                     LIMIT ?4"
                );
                let mut statement = connection.prepare(&query)?;
                let events = statement
                    .query_map(
                        params![action, cursor.value.as_deref(), cursor.id, limit],
                        map_audit_event,
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                events
            }
            (Some(action), None) => {
                let query = format!(
                    "{AUDIT_SELECT}
                     FROM audit WHERE action=?1
                     ORDER BY {column} {query_direction},id {query_direction}
                     LIMIT ?2"
                );
                let mut statement = connection.prepare(&query)?;
                let events = statement
                    .query_map(params![action, limit], map_audit_event)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                events
            }
            (None, Some(cursor)) => {
                let query = format!(
                    "{AUDIT_SELECT}
                     FROM audit
                     WHERE {column} {comparison} COALESCE(?1,(SELECT {column} FROM audit WHERE id=?2))
                        OR ({column} = COALESCE(?1,(SELECT {column} FROM audit WHERE id=?2)) AND id {comparison} ?2)
                     ORDER BY {column} {query_direction},id {query_direction}
                     LIMIT ?3"
                );
                let mut statement = connection.prepare(&query)?;
                let events = statement
                    .query_map(
                        params![cursor.value.as_deref(), cursor.id, limit],
                        map_audit_event,
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                events
            }
            (None, None) => {
                let query = format!(
                    "{AUDIT_SELECT}
                     FROM audit
                     ORDER BY {column} {query_direction},id {query_direction}
                     LIMIT ?1"
                );
                let mut statement = connection.prepare(&query)?;
                let events = statement
                    .query_map([limit], map_audit_event)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                events
            }
        };
        if position == AuditKeysetPosition::Before {
            events.reverse();
        }
        Ok(events)
    }

    pub fn audit_cursor_at_offset(
        &self,
        action: Option<&str>,
        offset: usize,
        column: AuditSortColumn,
        direction: AuditSortDirection,
    ) -> rusqlite::Result<Option<AuditCursor>> {
        let connection = self.try_conn()?;
        let column = audit_sort_expression(column);
        let direction = audit_sort_direction_sql(direction);
        if let Some(action) = action {
            let query = format!(
                "SELECT NULL,id FROM audit WHERE action=?1
                 ORDER BY {column} {direction},id {direction}
                 LIMIT 1 OFFSET ?2"
            );
            connection
                .query_row(&query, params![action, offset as i64], |row| {
                    Ok(AuditCursor {
                        value: row.get(0)?,
                        id: row.get(1)?,
                    })
                })
                .optional()
        } else {
            let query = format!(
                "SELECT NULL,id FROM audit
                 ORDER BY {column} {direction},id {direction}
                 LIMIT 1 OFFSET ?1"
            );
            connection
                .query_row(&query, [offset as i64], |row| {
                    Ok(AuditCursor {
                        value: row.get(0)?,
                        id: row.get(1)?,
                    })
                })
                .optional()
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

fn map_audit_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEvent> {
    Ok(AuditEvent {
        id: row.get(0)?,
        occurred_at: row.get(1)?,
        actor: row.get(2)?,
        action: row.get(3)?,
        object_id: row.get(4)?,
        detail: row.get(5)?,
        client_ip: row.get(6)?,
    })
}

fn audit_sort_expression(column: AuditSortColumn) -> &'static str {
    match column {
        AuditSortColumn::Time => "occurred_at",
        AuditSortColumn::Actor => "actor COLLATE NOCASE",
        AuditSortColumn::Action => "action COLLATE NOCASE",
        AuditSortColumn::Object => "COALESCE(object_id, '') COLLATE NOCASE",
        AuditSortColumn::Detail => "COALESCE(detail, '') COLLATE NOCASE",
        AuditSortColumn::ClientIp => "COALESCE(client_ip, '') COLLATE NOCASE",
    }
}

fn audit_sort_direction_sql(direction: AuditSortDirection) -> &'static str {
    match direction {
        AuditSortDirection::Ascending => "ASC",
        AuditSortDirection::Descending => "DESC",
    }
}

fn reverse_audit_sort_direction_sql(direction: AuditSortDirection) -> &'static str {
    match direction {
        AuditSortDirection::Ascending => "DESC",
        AuditSortDirection::Descending => "ASC",
    }
}

#[cfg(test)]
mod log_safety_tests {
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    use super::*;

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl io::Write for CapturedLogs {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn tracing_escapes_audit_fields_but_sqlite_retains_exact_values() {
        let _tracing_guard = crate::test_support::tracing_subscriber_guard();
        let actor = "admin\r\nforged";
        let object = "file\tname";
        let detail = "C1:\u{85};line:\u{2028}next";
        let captured = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::INFO)
            .with_writer(captured.clone())
            .finish();
        let database = Database::open(":memory:").unwrap();

        tracing::subscriber::with_default(subscriber, || {
            database
                .audit_action_with_client_ip(
                    AuditAction::SettingsUpdated,
                    actor,
                    Some(object),
                    Some(detail),
                    None,
                )
                .unwrap();
        });

        let output = String::from_utf8(
            captured
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
        .unwrap();
        let line = output.strip_suffix('\n').unwrap_or(&output);
        assert!(!line.chars().any(char::is_control), "{line:?}");
        assert!(!line.contains('\u{2028}'));
        assert!(line.contains("admin\\r\\nforged"));
        assert!(line.contains("file\\tname"));
        assert!(line.contains("C1:\\u{85};line:\\u{2028}next"));

        let events = database.list_audit(None, 1, 0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, actor);
        assert_eq!(events[0].object_id.as_deref(), Some(object));
        assert_eq!(events[0].detail.as_deref(), Some(detail));
    }
}
