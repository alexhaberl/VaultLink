use std::{error::Error, fmt};

use super::{audit::insert_audit_event, AuditAction};
use crate::log_safety::EscapedLogValue;

/// Nominal proof that a value was produced by a committed required-audit
/// transaction.
///
/// The tuple field is deliberately private and there is no public constructor
/// or extractor. Code outside the database module can transform the contained
/// value with [`Audited::map`], but only the database-owned required-audit job
/// adapter can release it to a transport adapter.
///
/// ```compile_fail
/// let _forged = vaultlink::db::Audited("not produced by a required-audit transaction");
/// ```
#[derive(PartialEq, Eq)]
pub struct Audited<T>(T);

impl<T> fmt::Debug for Audited<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Audited([REDACTED])")
    }
}

/// A mutation attempt either committed through the required-audit transaction
/// or was rejected before any mutation became durable.
///
/// This is used for compatibility paths such as uniqueness conflicts: callers
/// may construct `Rejected`, but cannot construct `Committed` without an
/// opaque [`Audited`] value from the database.
pub(crate) enum RequiredAuditDecision<T, R> {
    Committed(Audited<T>),
    Rejected(R),
}

pub(crate) enum RequiredAuditCompletion<T, R> {
    Committed(T),
    Rejected(R),
}

impl<T> Audited<T> {
    pub(super) fn new(value: T) -> Self {
        Self(value)
    }

    pub(crate) fn map<U>(self, operation: impl FnOnce(T) -> U) -> Audited<U> {
        Audited(operation(self.0))
    }

    /// Compatibility escape hatch for existing public `Database` methods.
    ///
    /// It is visible only inside `crate::db`; request transports must use the
    /// required-audit executor instead.
    pub(super) fn into_legacy_inner(self) -> T {
        self.0
    }

    #[cfg(test)]
    pub(crate) fn into_test_value(self) -> T {
        self.0
    }
}

/// Releases a required-audit proof at the transport boundary.
///
/// Keeping this extractor database-owned prevents services from accidentally
/// turning an audited mutation into an ordinary value before their caller can
/// require the nominal proof in its type signature.
pub(crate) fn release_audited<T>(audited: Audited<T>) -> T {
    let Audited(value) = audited;
    value
}

/// Releases a session-bound required-audit proof at the transport boundary.
pub(crate) fn release_session_audited<T>(
    outcome: super::SessionBound<Audited<T>>,
) -> super::SessionBound<T> {
    outcome.map(release_audited)
}

pub(crate) fn release_session_audit_decision<T, R>(
    outcome: super::SessionBound<RequiredAuditDecision<T, R>>,
) -> super::SessionBound<RequiredAuditCompletion<T, R>> {
    outcome.map(|decision| match decision {
        RequiredAuditDecision::Committed(audited) => {
            RequiredAuditCompletion::Committed(release_audited(audited))
        }
        RequiredAuditDecision::Rejected(rejection) => RequiredAuditCompletion::Rejected(rejection),
    })
}

pub(super) fn audited_job<T, F>(
    operation: F,
) -> impl FnOnce(super::Database) -> rusqlite::Result<T> + Send + 'static
where
    T: Send + 'static,
    F: FnOnce(super::Database) -> rusqlite::Result<Audited<T>> + Send + 'static,
{
    move |database| operation(database).map(|Audited(value)| value)
}

pub(super) fn audited_result_job<T, E, F>(
    operation: F,
) -> impl FnOnce(super::Database) -> Result<T, E> + Send + 'static
where
    T: Send + 'static,
    E: Send + 'static,
    F: FnOnce(super::Database) -> Result<Audited<T>, E> + Send + 'static,
{
    move |database| operation(database).map(|Audited(value)| value)
}

pub(super) fn audited_decision_job<T, R, F>(
    operation: F,
) -> impl FnOnce(super::Database) -> rusqlite::Result<RequiredAuditCompletion<T, R>> + Send + 'static
where
    T: Send + 'static,
    R: Send + 'static,
    F: FnOnce(super::Database) -> rusqlite::Result<RequiredAuditDecision<T, R>> + Send + 'static,
{
    move |database| {
        operation(database).map(|decision| match decision {
            RequiredAuditDecision::Committed(Audited(value)) => {
                RequiredAuditCompletion::Committed(value)
            }
            RequiredAuditDecision::Rejected(rejection) => {
                RequiredAuditCompletion::Rejected(rejection)
            }
        })
    }
}

pub(super) fn session_audited_job<T, F>(
    operation: F,
) -> impl FnOnce(super::Database) -> rusqlite::Result<super::SessionBound<T>> + Send + 'static
where
    T: Send + 'static,
    F: FnOnce(super::Database) -> rusqlite::Result<super::SessionBound<Audited<T>>>
        + Send
        + 'static,
{
    move |database| {
        operation(database).map(|outcome| match outcome {
            super::SessionBound::Authorized(Audited(value)) => {
                super::SessionBound::Authorized(value)
            }
            super::SessionBound::SessionUnavailable => super::SessionBound::SessionUnavailable,
        })
    }
}

pub(super) fn session_audited_result_job<T, E, F>(
    operation: F,
) -> impl FnOnce(super::Database) -> Result<super::SessionBound<T>, E> + Send + 'static
where
    T: Send + 'static,
    E: Send + 'static,
    F: FnOnce(super::Database) -> Result<super::SessionBound<Audited<T>>, E> + Send + 'static,
{
    move |database| {
        operation(database).map(|outcome| match outcome {
            super::SessionBound::Authorized(Audited(value)) => {
                super::SessionBound::Authorized(value)
            }
            super::SessionBound::SessionUnavailable => super::SessionBound::SessionUnavailable,
        })
    }
}

pub(super) fn run_session_audited<T, E, F>(
    database: &super::Database,
    operation: F,
) -> Result<super::SessionBound<T>, E>
where
    F: FnOnce(&super::Database) -> Result<super::SessionBound<Audited<T>>, E>,
{
    operation(database).map(|outcome| match outcome {
        super::SessionBound::Authorized(Audited(value)) => super::SessionBound::Authorized(value),
        super::SessionBound::SessionUnavailable => super::SessionBound::SessionUnavailable,
    })
}

pub(super) fn session_audited_decision_result_job<T, R, E, F>(
    operation: F,
) -> impl FnOnce(super::Database) -> Result<super::SessionBound<RequiredAuditCompletion<T, R>>, E>
       + Send
       + 'static
where
    T: Send + 'static,
    R: Send + 'static,
    E: Send + 'static,
    F: FnOnce(super::Database) -> Result<super::SessionBound<RequiredAuditDecision<T, R>>, E>
        + Send
        + 'static,
{
    move |database| operation(database).map(release_session_audit_decision)
}

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
        // A third-party tracing subscriber is allowed to fail, but it must not
        // unwind across an already-committed security transaction and make the
        // caller observe a false rollback. SQLite remains the required audit
        // sink; tracing is explicitly best-effort fallback telemetry.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tracing::info!(
                target: "vaultlink::audit",
                actor = %EscapedLogValue::new(&context.actor),
                action = event.action.as_str(),
                object_id = %EscapedLogValue::new(event.object_id.as_deref().unwrap_or("")),
                detail = %EscapedLogValue::new(event.detail.as_deref().unwrap_or("")),
                "audit event"
            );
        }));
    }
}
