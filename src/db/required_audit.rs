use std::{error::Error, fmt};

use super::{audit::insert_audit_event, AuditAction};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditContext {
    pub actor: String,
    pub client_ip: Option<String>,
}

impl AuditContext {
    pub fn new(actor: impl Into<String>, client_ip: Option<String>) -> Self {
        Self {
            actor: actor.into(),
            client_ip,
        }
    }

    pub fn system() -> Self {
        Self::new("system", None)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequiredAuditEvent {
    pub(crate) action: AuditAction,
    pub object_id: Option<String>,
    pub detail: Option<String>,
}

impl RequiredAuditEvent {
    pub(crate) fn new(
        action: AuditAction,
        object_id: Option<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            action,
            object_id,
            detail,
        }
    }
}

#[derive(Debug)]
struct AuditUnavailableError(rusqlite::Error);

impl fmt::Display for AuditUnavailableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "required audit insert failed: {}", self.0)
    }
}

impl Error for AuditUnavailableError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

pub fn is_audit_unavailable(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::ToSqlConversionFailure(source)
            if source.downcast_ref::<AuditUnavailableError>().is_some()
    )
}

pub(super) fn insert_required_audits(
    transaction: &rusqlite::Transaction<'_>,
    context: &AuditContext,
    events: &[RequiredAuditEvent],
) -> rusqlite::Result<()> {
    for event in events {
        insert_audit_event(
            transaction,
            event.action,
            &context.actor,
            event.object_id.as_deref(),
            event.detail.as_deref(),
            context.client_ip.as_deref(),
        )
        .map_err(|error| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(AuditUnavailableError(error)))
        })?;
    }
    Ok(())
}

pub(super) fn trace_required_audits(context: &AuditContext, events: &[RequiredAuditEvent]) {
    for event in events {
        // Client IP retention is SQLite-only. Never mirror it into tracing/journald.
        tracing::info!(
            target: "vaultlink::audit",
            actor = context.actor,
            action = event.action.as_str(),
            object_id = event.object_id.as_deref().unwrap_or(""),
            detail = event.detail.as_deref().unwrap_or(""),
            "audit event"
        );
    }
}
